# Overview
Intel CET is a hardware assisted mitigation against control-flow hijacking attacks in Intel x86 and x86-64 processors. It introduces two new mitigation techniques:  
- [[#^be1b31|SHSTK]]
- [[#^d764c4|IBT]]

SHSTK and IBT exist to deal with [[#^54ccb0|ROP]] and [[#^976c8f|JOP]]/[[#^4cae67|COP]] respectively. Specifically SHSTK is a backward-edge [[#^cd12c6|CFI]] mitigation and IBT is a forward-edge CFI mitigation.  

CET requires a complex and thorough chain of support from both hardware and software. Since hardware and software implementation details both are quite extensive, we will structure the following document into multiple parts.

# Where does CET fit?
CET is a cross between a reactive and a proactive measure. It kicks in after memory has already been corrupted and tries to stop an attacker from developing that into a control flow primitive.   
Typically after memory corruption, there are two main ways for an attacker to take control of the [[#^c1ec26|IP]] and hijack the control flow to perform malicious behavior:
1. ## Overwrite the Return Address (Backward Edge)
   Attackers can overwrite the return address of a function on the function stack. When a function returns, this address is popped off the stack and placed in the IP register. If an attacker controls this address they can divert control flow to an address of their liking and execute instructions from there.  
   ROP is one of the techniques that can be used to create an exploit after getting control of the return address. Attackers can chain together a series of instructions already available within the executable sections of the program to create their own malicious program that runs inside the target process.  
   Typically one link (or gadget) in a ROP chain consists of a set of one or more instructions that end with the `ret` instruction. This means that after each gadget executes, there will be a `return` which leads to the next gadget in the chain. Hence the name Return Oriented Programming.  
   To mitigate this, shadow stacks can be used. A shadow stack is a secondary stack that cannot be modified even if an attacker obtains memory corruption on the regular stack. When a function is called, the return address is pushed on both the regular stack and the shadow stack. When the `ret` instruction is executed, the return address is popped off the regular stack and the shadow stack and then compared with one another. If they don't match, as is the case when an attacker overwrites the return address, the CET mechanism triggers an exception and process execution is terminated.
2. ## Overwrite an Address on the Forward Edge
   Many programs contain mutable addresses on the forward edge e.g. function pointers, jump tables, v-tables for class methods, etc. These addresses are used in indirect branch statements e.g. `jmp rax` or `call rcx`, instead of the typical direct branches e.g. `jmp 0x4010` . If an attacker controls one or more of these addresses, they can point it towards a ROP gadget, thereby triggering a ROP chain. They can also point it towards a JOP/COP gadget.
   COP and JOP are similar to ROP. JOP consists of a sequence of instructions that end with a `jmp` or similar instruction. COP consists of a sequence of instructions that end with a `call` statement
   To mitigate this, Indirect Branch Tracking can be used. The code that the IP jumps to after a [[#^1f7552|branch instruction]] is called a [[#^d2bc84|branch target]]. If the target is an [[#^661483|indirect branch]], compilers can place a special `endbr64` or `endbr32` end-branch instruction to specify that it is a valid branch target. When IBT is enabled, all indirect branch instructions must resolve to a target that has the end-branch instruction otherwise the CET mechanism triggers an exception and process execution is terminated.

# Hardware Specification
The CET implementation in hardware consists of extensions to the Intel x86 and x86-64 [[#^4bf34c|ISA]]. 

## Control Protection Exception (#CP)
CET introduces a new Control Protection (#CP) exception class with interrupt vector 21. This exception is raised when a control flow instruction results in a transfer that violates the constraints introduced by CET.  

> ❗**NOTE:** The CP exception occurs before the control flow instruction is actually executed

CP is part of the contributory class of exceptions which means that if another contributory exception is raised during CP handling, it will trigger a Double Fault.

![[Pasted image 20250703163556.png]]

When this exception is raised, an error code is pushed on the stack which tells the CP exception handler what event caused the exception. An exception may be raised by the following events:
- SHSTK violation after near `ret`
- SHSTK violation after far `ret`
- SHSTK violation after `iret`
- Missing `endbr` instruction at indirect branch target
- Token check failure after `rstorssp`
- Token check failure after `setssbsy`

The contents of the CS and IP registers are saved to keep track of what instruction caused the CP exception.

## CET Components
As we discussed before, CET is a name for two mitigation techniques. SHSTK and IBT. From an implementation perspective, these can be further broken down in the following: 
- Supervisor Shadow Stack or Kernel Shadow Stack
- User Space Shadow Stack
- Kernel IBT
- User Space IBT

## Enabling CET in the Hardware
To enable CET in the hardware, bit 23 of the CR4 register must be set. This is also known as CR4.CET or the CET Master Enable.
Setting this bit does not mean SHSTK and IBT will work. Each CET feature must be enabled on its own using an [[#^bf5096|MSR]]. The following two MSR's are available for CET features:
- `MSR IA32_U_CET (0x6A0)`: User space CET
- `MSR IA32_S_CET (0x6A2)`: Kernel space CET
There are 5 other MSR's that store shadow stack addresses for different [[#^ac2db0|ring privilege levels]].

> ❗**NOTE:** User space CET refers to `CPL3` and Kernel space CET refers to `CPL0` in the ring privilege model

The above two MSR's both follow the same format:


|  Bit  |     Feature Name     |                   Description                   |
| ----- | -------------------- | ----------------------------------------------- |
| 0     | `SH_STK_EN`          | Enable shadow stack                             |
| 1     | `WR_SHSTK_EN`        | Enable WRSS                                     |
| 2     | `ENBR_EN`            | Enable IBT                                      |
| 3     | `LEG_IW_EN`          | Enable legacy IBT support                       |
| 4     | `NO_TRACK_EN`        | Enable the `notrack` prefix                     |
| 5     | `SUPPRESS_DIS`       | Disable IBT suppression                         |
| 6-9   | `RSVD`               | Reserved (always 0)                             |
| 10    | `SUPPRESS`           | Suppress IBT                                    |
| 11    | `TRACKER`            | Tracks the state of the IBT state machine       |
| 12-63 | `EB_LEG_BITMAP_BASE` | Address of valid branch targets without `endbr` |

Setting the MSR bits as shown in the above table enables and configures CET features as needed. As we can see, there is some new terminology in the table, so let's now discuss those.

### WRSS (Write to Shadow Stack)
The `WR_SHSTK_EN` flag enables the `wrss` instruction. This allows writes to the shadow stack in a controlled manner. Manual writes to the shadow stack may only be done via this instruction. Directly writing to shadow stack memory by dereferencing a pointer is not allowed.

### Legacy IBT Support
The `LEG_IW_EN` flag enables support for IBT enabled systems to run non IBT supported code. This allows code running with IBT support to perform indirect jumps into code that is not built with IBT support i.e. code that does not have `endbr` on the indirect branch targets.  
The `EB_LEG_BITMAP_BASE` field contains an address to a bitmap. This bitmap points to pages in memory that contain legacy code without the `endbr` instruction. On a system where IBT is enabled and `SUPPRESS` is not set, a process may perform an indirect jump into any page referred to by this bitmap without raising  a CP exception.

### No Track
The `NO_TRACK_EN` flag enables the use of the `notrack` instruction. Prefacing an indirect branch instruction with `notrack`, disables IBT for that specific control flow transfer e.g.
`notrack call [rax]`.

### IBT Suppression
The `SUPPRESS` and `SUPPRESS_DIS`flags are used to control the ability of the IBT mechanism to raise the CP exception. When `SUPPRESS` is enabled, IBT wont raise an exception. When `SUPRRESS_DIS` is enabled, the value of the `SUPPRESS` flag will be ignored and raising CP will not be blocked.

### RSVD (Reserved)
These bits of the MSR are reserved for potential future use. For now, they must always be set to 0.

### Tracker
This bit tracks the state of the IBT state machine. The IBT state machine has 2 possible states:
- `0`: IDLE
- `1`: WAIT_FOR_ENDBRANCH
When an indirect branch instruction is executed, the IBT state machine enters the WAIT_FOR_ENDBRANCH state. When an `endbr` instruction is encountered, the state machine returns to the IDLE state.


## Shadow Stack
The shadow stack is a secondary stack that is managed parallel to each program stack. It is only used for storing data relevant to control flow operations.

# References
- Intel® Control-Flow Enforcement Technology Specification Document Number: 334525-003, Revision 3.0 https://kib.kiev.ua/x86docs/Intel/CET/334525-003.pdf
- Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume 3 (Section: Interrupt and Exception Handling) https://cdrdv2.intel.com/v1/dl/getContent/671447
- Shadow stacks for user space https://lwn.net/Articles/885220/

# Appendix
- **CET**: Control-Flow Enforcement Technology
- **SHSTK**: Shadow Stack ^be1b31
- **IBT**: Indirect Branch Tracking ^d764c4
- **ROP**: Return Oriented Programming ^54ccb0
- **JOP**: Jump Oriented Programming ^976c8f
- **COP**: Call Oriented Programming ^4cae67
- **CFI**: Control Flow Integrity ^cd12c6
- **IP**: Instruction Pointer. Also known as Program Counter (PC) ^c1ec26
- **Branch Instruction**: An instruction that diverts control flow from the normal sequential flow e.g. `jmp`, `call`, `loop` ^1f7552
- **Branch Target**: The address that is loaded into the IP after a branch instruction is executed ^d2bc84
- **Direct Branch**: A branch whose target is predetermined and usually immutable. Typically these are offsets from the IP
- **Indirect Branch**: A branch whose target is variable and computed at run-time ^661483
- **ISA**: Instruction Set Architecture ^4bf34c
- **#CP**: Control Protection Exception in Intel x86 and x86-64 processors
- **MSR**: Model Specific Register. Registers in CPU's that are used to enable or disable processor specific features. ^bf5096
- **Ring Privilege Level**: Levels in the ring privilege model for CPU's, i.e. `CPL0 - CPL3` ^ac2db0