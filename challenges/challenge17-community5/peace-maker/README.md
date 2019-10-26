# A solution for the community challenge 5

The challenge is a x86 binary which prints the output of `/bin/ls -A1 *.txt` once and goes into an endless loop letting us select files to print.
The input is sanitized by null-ing the following characters: `\n`, `\r`, `'`, `/` and `\`. Afterwards the input is formatted into `"$PROG '%s'"`, while `$PROG` is set to `/bin/cat`, and passed to `system`. Due to the sanitization, we can't escape the quotes and inject a command, nor traverse the filesystem.

```
Arch:     i386-32-little
RELRO:    FULL RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

The filename input is read into a buffer on the stack of `main`, while largely overflowing it. But what is there to change? Stack canaries are enabled and `main` never returns due to the endless loop, so the return address isn't a viable target. The format buffer where our input is copied into with `$PROG` appended is in .bss and the buffer size and copy size match.

It's suspicious that the program to execute is in an environment variable instead of being hard coded. `system` inherits the environment from the parent process. If we'd be able to change the `PROG` environment variable, we can execute whatever command we like.

The stack of `main` looks roughly like this:
```
[local vars]
canary
return address
...
[arguments argc, argv, envp]
...
argc
argv[0]
...
NULL
...
envp[0] <-- target
envp[1]
envp[2]
...
NULL
...
[actual argv and envp strings]
```

So by overwriting all pointers in envp with NULL, `system` spawns a process with an empty environment. `$PROG` gets replaced by nothing and just our argument is executed as a command. Bash is nice enough to treat `/bin/id` and ` '/bin/id'` the same, so we can now put any command as our "filename" and have it executed.

## Famous one-liner:
```bash
$ { python -c "print('sh'.ljust(0x400, '\x00'))"; cat; } | ./connect.sh
```

Shoutouts to spq!
