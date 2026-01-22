---
title: "Patching Crystal Palace: bypassing detection"
date: 2026-01-22 13:00:00 +0800
categories: [Malware devolopment, Red team]
tags: [Red team, Malware devolopment]
---

Lately I've been studying CRTL which focuses on developing offensive tradecraft using Crystal palace framework. I never had the chance to use it before this, so am not an expert in any type of way.


I read Rasta's blog about "Cracking the Crystal Palace", which goes deep in how crystal palace work and how to detect it. The yara rule Rasta's wrote focuses on the  `__resolve_hook()` which is responsible for hooking the APIs in the prepended dll or the beacon dll in our case, and then redirect it to our tradecraft (e.g. indirect syscalls/call stack spoofing).

_The rule_ :

```
rule Windows_Shellcode_CrystalPalace_HookIntrinsic {
    meta:
        author = "Rasta Mouse"
        description = "Identifies Crystal Palace's __resolve_hook() intrinsic"
        threat_name = "Windows.Shellcode.CrystalPalace"
        creation_date = "2025-11-29"
        last_modified = "2025-11-29"
        arch_context = "x86"
        scan_context = "file, memory"
        os = "windows"
        license = "bsd"
    strings:
        $a = { 89 C1 81 F9 ?? ?? ?? ?? 75 ?? 48 8D ?? ?? ?? ?? ?? E? ?? }
    condition:
        all of them
}
```


The rule detects the pattern made by the `__resolve_hook()` intrinsic : 


```
89C1                 mov       %eax,%ecx
81F9A8A24DBC         cmp       $0x91AF`CA54,%ecx
7509                 jne       0x0000`0000`0000`0035
488D055F010000       lea       _VirtualAlloc,%rax
EB03                 jmp       0x0000`0000`0000`0038
```

> We can see here that the pattern is very recognizable `mov`, `cmp`, `jne`, `lea`, `jmp` . 

Now I was thinking where can find this function that is responsible for the hooking and how can I even change this without breaking the logic. After looking through each file in Crystal palace I finally found the function I want. 

_\cpsrc\src\crystalpalace\btf\pass\hook\ResolveHooks.java_
```java
public void generateResolver_x64(CodeAssembler program, RebuildStep step) {
		AsmRegister64 rax = new AsmRegister64(ICRegisters.rax);
		AsmRegister32 ecx = new AsmRegister32(ICRegisters.ecx);

		/* create our done CodeLabel */
		CodeLabel done = program.createLabel();

		/* walk our set of various IAT hooks that the user registered */
		Iterator i = hooks.getResolveHooks().iterator();
		while (i.hasNext()) {
			Hooks.ResolveHook reshook  = (Hooks.ResolveHook)i.next();
			Symbol            wrapper  = null;
			String            hookfunc = null;

			/* determine which hook to use, an explicit one or one attached to the API */
			if (reshook.isSelf()) {
				hookfunc = hooks.getHook(step.getFunction(), reshook.getTarget());
			}
			else {
				hookfunc = reshook.getWrapper();
			}

			/* get all of it, I guess */
			wrapper = object.getSymbol(hookfunc);
			if (wrapper == null)
				continue;

			/*
			 * cmp [ror13 hash], %rcx
			 * jne next
			 * lea [label to wrapper], %rax
			 * jmp done
			 * next:
			 */
			program.cmp(ecx, reshook.getFunctionHash());
			program.jne(program.f());
			program.lea( rax, AsmRegisters.mem_ptr(step.getLabel(hookfunc)) );
			program.jmp(done);

			program.anonymousLabel();
		}

		/* our default result, which is to put 0 in %eax */
		program.xor(rax, rax);

		/* this is the exit point for the whole thing */
		program.label(done);
	}
```

> The `generateResolver_x64` function is responsible for the pattern we saw earlier.  


## Understanding the original logic 


The core of the `generateResolver` function's logic is this :

```

			/*
			 * cmp [ror13 hash], %rcx
			 * jne next
			 * lea [label to wrapper], %rax
			 * jmp done
			 * next:
			 */
			program.cmp(ecx, reshook.getFunctionHash());
			program.jne(program.f());
			program.lea( rax, AsmRegisters.mem_ptr(step.getLabel(hookfunc)) );
			program.jmp(done);

```

Basically, this compares each hooked function by its **ROR13** hash against the hash of the API name being resolved at runtime. If the hash matches, the hook wrapper is loaded into `rax`.

> The run time computed hash is produced by using `ror13hash()` on the API name(`lpProcName`) inside the hooked `_GetProcAddress`.

```c
FARPROC WINAPI _GetProcAddress ( HMODULE hModule, LPCSTR lpProcName )
{
    FARPROC result = __resolve_hook ( ror13hash ( lpProcName ) );
    
    if ( result != NULL ) {
        return result;
    }

    return GetProcAddress( hModule, lpProcName );
}
```


### Breaking the signature

At this point, the issue is not what the function does but rather how it is expressed in assembly. The original implementation relies on the `cmp` instruction to test "equality" between the API hash that was computed at build time with the one that is computed at run-time. After digging a bit on how can this be changed, I found out that `cmp` isn't the only way to do this.


We can simply use `xor` instead of the `cmp`, so we XOR both of the values and test the results. If the two values are equal the result is 0, if they are different its non-zero, simple.

The modified code : 

```
program.cmp(ecx, reshook.getFunctionHash());
program.jne(program.f());
```

with :
```
program.mov(edx, ecx);
program.xor(edx, reshook.getFunctionHash());
program.jne(program.f());
```

-----

## Bypassing the rule !


Now after recompiling crystal palace and generating our new payload, lets see the unedited version disassembled : 

![Unedited ](/images/Pasted image 20260122134848.png)

> The highlighted value is the ROR hash of `VirtualAlloc` API



We can see that it gets caught be the yara rule :

![YARA 1](/images/Pasted image 20260122134954.png)

Now lets try our edited crystal palace :

![XOR ](/images/Pasted image 20260122151743.png)

We can see the `xor` instruction there so it should work, lets now actually test if it bypasses the YARA rule :

![bypass](/images/Pasted image 20260122151658.png)
Bypassed ...

> This also works on a running process I just forgot to take screenshots of the running beacon ):

