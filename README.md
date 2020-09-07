Some years ago, I did a process protection tool. The protection tool is to secure a specific process. No other unauthorized codes can access to it. 

This repository shows the core part of the project.

The inline hook technique is widely used in anti-virus or protection. Here are some samples for my project. These codes should run on Windows OS.

Application layer Inline hook sample.

Let’s assume malicious codes want to damage our codes. The malicious codes should use some very important API functions. With inline hook. We can monitor these core API like OpenProcess(), ReadProcessMemory(), WriteProcessMemory() and etc. Here I give a sample to monitor MessageBoxA().

Application layer hook:

1.1. First gets the address of the original MessageBoxA().

1.2. Then I write machine codes “E9XXXX” (E9 means jmp. XXXX means address I got in the former step). XXXX=object address-current address-5. Why? It relates address offset. Why minus 5? Because “E9XXXX” is 5 bytes.

1.3. We construct our own return function. With standard function head:

push ebp mov ebp, esp

1.4. So when calling MessageBoxA(), it will auto return to my function to execute our codes first..

Kernel layer Inline hook sample.

Assume malicious code wants to change our memory data. The first step malicious code will do is to OpenProcess(). Then Windows passes OpenProcss() to kernel NtOpenProcess(). Then our goal is to hook this kernel function

2.1. Get the original address of this function from ServiceDescriptorTable. And calculate its offset toward the base address.

2.2.mov ebx,original_address

mov byte ptr ds:[ebx],0xE9//E9 means jmp mov eax,ourfunction_address

mov DWORD ptr ds:[ebx+1],eax//+1 mean E9 already took 1 byte

2.3. When called NtOpenProcess(), our function will handle it.

2.4. If not authorized one attempt, our function will erase ProcessHandle and retn 0x10. 0x10 means the original function has four parameters. If comes from authorized one, then do the following.

push	0C4h

mov eax,original_address // add eax,5

jmp eax

push 0C4h is because original head of NtOpenProcess() is push 0C4h. Our jmp+address took 5 bytes.

