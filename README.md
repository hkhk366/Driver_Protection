In the past, I did a game protection software. The protection software is ensure security of a specific process. No other unauthorized codes can access to it. But, I didn’t bring full codes here. And I sell this software to others. So this is not an open-source project. According to the sale agreement, I can’t show others the full codes. I wish you can understand. But I can show you core thoughts or core structure of this software. Let’s you know what I did in this project. If you have any question about this, please let me know.

In line hook is widely used in anti-virus or protection. Here are some samples for my protect software. This codes should run on Windows OS.

1. Application layer Inline hook sample.

Let’s assume malicious codes want to damage our codes. The malicious codes should use some very important API functions. With inline hook. We can monitor these core API like OpenProcess(), ReadProcessMemory(), WriteProcessMemory() and etc. Here I give a sample to monitor MessageBoxA().

Overview of following codes:
1.1.First gets the address of the original MessageBoxA().
1.2.Then I write machine codes “E9XXXX” (E9 means jmp. XXXX means address I got in the former step). XXXX=object address-current address-5. Why? It relates address offset. Why minus 5? Because “E9XXXX” is 5 bytes.
1.3.We construct our own return function. With standard function head:
push ebp mov ebp, esp
1.4.So when calling MessageBoxA(), it will auto return to my function. Then my function can monitor this function whether this is called by an authorized process or function. If comes from an authorized one then jmp to its original address. If not, jmp to the retn of original function.


2. Kernel layer Inline hook sample.


