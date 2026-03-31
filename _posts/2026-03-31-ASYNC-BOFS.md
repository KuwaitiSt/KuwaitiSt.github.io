---
title: "ASYNC BOFs: When you just can't wait"
date: 2026-03-31 20:00:00 +0800
categories: [Malware devolopment, Red team]
tags: [Red team, Malware devolopment]
---

## Introduction 


In this blog I'll be going over my implementation on ASYNC-BOFs + EKKO sleep mask. The implementation is no where near perfect It's left to the reader to work on the idea and make it better.

The issue with normal BOFs is that they block the agent during execution. While the BOF execute the agent can't check-in or receive new tasks. So basically, if the BOF runs for an N seconds the agent is dead for an N seconds, therefore the agent is unencrypted sitting waiting for the EDR's memory scanner to take the shot.

The goal is that we want to make the BOF execute at the same time, we want the agent to be fully responsive.




![GIF 11](/images/gifff.gif)





### Async Bof - Direct approach


The direct implementation of Async-Bof is creating a new thread executing the COFF loading function. The agent main thread sleeps using `WaitForSignleObject` with the handle of the "wake up" event.

We can see this exact implementation in Adaptix C2's beacon code :

_Boffer.cpp_
```cpp


this->wakeupEvent = ApiWin->CreateEventA(NULL, TRUE, FALSE, NULL);



----

BOOL Boffer::StartAsyncBof(AsyncBofContext* ctx)
{
    if (!ctx)
        return FALSE;
    
    ApiWin->EnterCriticalSection(&this->managerLock);
    
    ctx->hThread = ApiWin->CreateThread(NULL, 0, AsyncBofThreadProc, ctx, 0, &ctx->threadId);
    if (!ctx->hThread) {
        ApiWin->LeaveCriticalSection(&this->managerLock);
        return FALSE;
    }
    
    this->asyncBofs.push_back(ctx);
    
    ApiWin->LeaveCriticalSection(&this->managerLock);
    return TRUE;
}
```

_WaitMask.cpp_
```cpp
    if (hEvent) {
        DWORD waitResult = ApiWin->WaitForSingleObject(hEvent, maxSleepTime);
        if (waitResult == WAIT_OBJECT_0)
            ApiWin->ResetEvent(hEvent);
    }
```


#### The problem 

Now why don't we use this method with sleepmask. The reason is in the COFF loading process we resolve all functions used by the object file Win32 and most importantly our BeaconAPIs ( e.g. `BeaconPrintf`). When the sleep mask encrypts the agent, the BOF being executed would need to use the "Beacon APIs" that were resolved and point somewhere within the agent code, but the agent's code is encrypted which would lead to a crash.




### The DLL solution 

Now since I couldn't make the agent do this all alone. I decided to make a new dll that will hold all the BeaconAPIs and the COFF loading process so I don't have to deal with the BeaconAPIs being encrypted in the agent. Now they should point to the external DLL loaded by the agent.


#### The implementation for the agent goes like this : 

1. The agent loads the Coff_loader.dll and get the exported function that is responsible to load the object file


2. Next, we create the pipe for the communication between the dll and the implant (where the output of the BOF will be).

```cpp
HANDLE hPipe = CreateNamedPipeA(pipename,......);
```

3. Finally, we create a named event that will be signaled to wake up the agent from it's sleep obfuscation.

```cpp
g_WakeUp = CreateEventA(NULL, TRUE, FALSE, EvntName);
```

Now we can create a new thread that will execute the COFF loading passing a structure that holds the name of the event and the pipe name and whatever is needed.


#### The implementation in the CoffLoader :

1. After the function calls the BOF entry the COFF loader sends the output to the pipe that was created by the agent earlier

```cpp
HANDLE hPipe = CreateFileA(pipename, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
/*
WRITING OUTPUT TO THE PIPE 
*/
```

2. Next, it opens the event by the event name, and signals it.

```cpp
HANDLE hEvent = OpenEventA(EVENT_MODIFY_STATE, FALSE, EvntName);
SetEvent(hEvent);
```


Now in the agent side the only thing we're going to change in the EKKO sleep is the 3rd CONTEXT that is the real waiting, to wait for the event signal from the COFF loader after the BOF finish execuiting.


```cpp
Ctx[3].Rip = U_PTR(WaitForSingleObjectEx);

if(g_WakeUp) {
	Ctx[3].Rcx = U_PTR(g_WakeUp);
} else {
	Ctx[3].Rcx = U_PTR(GetCurrentProcess());
}
Ctx[3].Rdx = U_PTR(dwTimeOut);
Ctx[3].R8 = U_PTR(FALSE);
```

> Make sure to reset the event in in the agent's loop using `ResetEvent(g_WakeUp)` 



### Results

Instead of implementing this on an agent I coded a POC to show the that the logic works :


- POC.exe : This will simulate the agent loop, it will initialize the event and the pipe and preforms EKKO sleep obfuscation. The code is taken from Maldev Academy, and was adjusted to follow our logic. POC.exe will take a `whoami.o` as a argument that will be loaded into the memory and passed to the COFF loader dll.


- CoffLoader.dll : This dll will be in the same directory and will be loaded by the POC.exe. It's a basic COFF loader with few additions that were mentioned above.

- Finally  a normal `whoami.o` BOF from **TrustSec** repo I only added `KERNEL32$Sleep(8000);` to slow it down so the agent fully sleeps.


<video width="700" controls autoplay muted loop>
  <source src="/images/demo.mp4" type="video/mp4">
</video>





## Conclusion 


The implementation is pretty raw I'd say, I think its a project that can be done more properly, the goal of this blog isn't to show you something never seen but I wanted to learn more about ASYNC-BOFs and decided to document my journey. 



### Credits 

- Maelstrom : The reason I even looked into async BOFs . Helped me a lot during my research.

-  https://www.outflank.nl/blog/2025/07/16/async-bofs-wake-me-up-before-you-go-go/

- https://maldevacademy.com/



