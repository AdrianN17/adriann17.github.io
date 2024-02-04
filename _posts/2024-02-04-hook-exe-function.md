---
layout: post
title: "How to hook a exe function address"
img_path: /assets/img/posts/how-to-hook-a-exe-function-address/

categories: [Reversing, Windows]
tags: [Hooking]
---

Hello everyone, this it's my first post about reverse engineering.

Today, I make an easy and understandable tutorial about how to hook a specific function of a executable, using its address to change the result of a string. For than purpose I made an easy executable with those functionalities.

Don't worry if you are a newbie (me too), I'm going to explain all the steps to make your first hook.

![Alt text](Pasted image 20240204003959.png)
## Configuring your local laboratory

In this example I'm using some Reversing tools, such as:
- Ghidra
- x64dbg
- Visual Studio 2022

Also, I'm sharing the source code if you want to try it yourself.

Source code exe target:

```c++
//testexe.cpp
#include <iostream>
#include <conio.h>

__declspec(noinline) void greeting()
{
    std::cout << "Hello world" << std::endl;
}

int main() {
    char key;

    while (true) {
        //std::cout << "Press 'h' to print Hello, world. Press 'q' to exit." << std::endl;

        // Wait until a key is pressed
        key = _getch();

        // Check the pressed key
        if (key == 'h' || key == 'H') {
            greeting();
        }
        else if (key == 'q' || key == 'Q') {
            std::cout << "Exiting the program." << std::endl;
            break;
        }
        else {
            std::cout << "Unrecognized key." << std::endl;
            auto address_greeting = reinterpret_cast<void*>(&greeting);

            // Print the address of the greeting function
            std::cout << "Address of the greeting function: " << address_greeting << std::endl;
        }
    }

    return 0;
}
```

Source code dll to inject:

```c++
//evildll.cpp
#include "pch.h"
#include <Windows.h>
#include <iostream>
#include <detours.h>

// Definition of the pointer to the original function
typedef void (*GreetingFunc)();

// Pointer to the original function
GreetingFunc greetingOriginal = nullptr;

// New implementation of the function (hook)
void greetingHook()
{
    MessageBoxW(NULL, L"Hello, World!", L"Hello World App", MB_ICONINFORMATION);
    std::cout << "Hooked: Hello from the DLL" << std::endl;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        uintptr_t functionAddress = 0x00007FF621251000; // Replace with the actual address of the original function

        greetingOriginal = reinterpret_cast<GreetingFunc>(functionAddress);

        // Check if obtaining the address was successful
        if (greetingOriginal == nullptr)
        {
            // Handle the error, for example, display a message or log to a file
            MessageBox(NULL, L"Failed to obtain the address of the original function.", L"Error", MB_OK | MB_ICONERROR);
            return FALSE;
        }

        // Start hooking when the DLL is loaded
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(reinterpret_cast<PVOID*>(&greetingOriginal), greetingHook);
        DetourTransactionCommit();
        break;
    }
    case DLL_PROCESS_DETACH:
    {
        // Restore hooking when the DLL is unloaded
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(reinterpret_cast<PVOID*>(&greetingOriginal), greetingHook);
        DetourTransactionCommit();
        break;
    }
    }
    return TRUE;
}
```

Source code injector

```c++
//injector.cpp
#include <iostream>
#include <locale>
#include <codecvt>
#include <windows.h>   
#include <tlhelp32.h>

int getPIDbyProcName(const WCHAR* procName) {
    int pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnap, &pe32) != FALSE) {
        while (pid == 0 && Process32Next(hSnap, &pe32) != FALSE) {
            if (_wcsicmp(pe32.szExeFile, procName) == 0) {
                pid = pe32.th32ProcessID;
            }
        }
    }
    CloseHandle(hSnap);
    return pid;
}

typedef LPVOID memory_buffer;

bool fileExists(const std::wstring& filePath) {
    DWORD fileAttributes = GetFileAttributes(filePath.c_str());
    return (fileAttributes != INVALID_FILE_ATTRIBUTES && !(fileAttributes & FILE_ATTRIBUTE_DIRECTORY));
}

int wmain(int argc, wchar_t* argv[]) {
    HANDLE pHandle; 
    HANDLE remoteThread;
    memory_buffer rb;

    if (argc != 3) {
        std::wcerr << L"Usage: " << argv[0] << L" <process name> <DLL path>" << std::endl;
        return 1;
    }

    std::wstring procName = argv[1];
    std::wstring evilDLL = argv[2];

    if (!fileExists(evilDLL)) {
        std::wcerr << L"Error: The specified DLL file path does not exist." << std::endl;
        return 1;
    }

    unsigned int evilLen = static_cast<unsigned int>((evilDLL.length() + 1) * sizeof(wchar_t));

    std::wcout << L"evilDLL: " << evilDLL << std::endl;
    std::wcout << L"Size of evilDLL: " << evilLen << L" bytes" << std::endl;

    // Get the PID of the process by name
    int pid = getPIDbyProcName(procName.c_str());

    // Open the process
    pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (pHandle == NULL) {
        std::wcerr << L"Error opening the process. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    // Allocate memory in the remote process
    rb = VirtualAllocEx(pHandle, NULL, evilLen, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);

    if (rb == NULL) {
        std::wcerr << L"Error allocating remote memory. Error code: " << GetLastError() << std::endl;
        CloseHandle(pHandle);
        return 1;
    }

    // Write the malicious code into the remote memory
    if (!WriteProcessMemory(pHandle, rb, evilDLL.c_str(), evilLen, NULL)) {
        std::wcerr << L"Error writing to remote memory. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(pHandle, rb, 0, MEM_RELEASE);
        CloseHandle(pHandle);
        return 1;
    }

    // Get the address of LoadLibraryW
    HMODULE hKernel32 = GetModuleHandle(L"Kernel32");

    if (hKernel32 == NULL) {
        std::wcerr << L"Error obtaining the handle of Kernel32. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(pHandle, rb, 0, MEM_RELEASE);
        CloseHandle(pHandle);
        return 1;
    }

    void* lb = GetProcAddress(hKernel32, "LoadLibraryW");

    if (lb == NULL) {
        std::wcerr << L"Error obtaining the address of LoadLibraryW. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(pHandle, rb, 0, MEM_RELEASE);
        CloseHandle(pHandle);
        return 1;
    }

    // Create a remote thread to execute LoadLibraryW with the name of the malicious DLL
    remoteThread = CreateRemoteThread(pHandle, NULL, 0, (LPTHREAD_START_ROUTINE)lb, rb, 0, NULL);

    if (remoteThread == NULL) {
        std::wcerr << L"Error creating the remote thread. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(pHandle, rb, 0, MEM_RELEASE);
        CloseHandle(pHandle);
        return 1;
    }

    std::wcout << L"DLL injected successfully into the process with PID: " << pid << std::endl;

    // Wait for the remote thread to finish before exiting
    WaitForSingleObject(remoteThread, INFINITE);

    // Clean up resources
    VirtualFreeEx(pHandle, rb, 0, MEM_RELEASE);
    CloseHandle(pHandle);
    CloseHandle(remoteThread);

    return 0;
}
```

First of all I need to clarify about my local exe names with a equivalent table:

| exe/dll in my PC | source name in your PC |
| ------------ | ------------ |
| ConsoleApplication1.exe | injector.cpp |
| ConsoleApplication2.exe | textexe.cpp |
| HookEXEDll.dll | evildll.cpp |

With that, we can avoid some mistakes with the pictures, sorry about that.

## Searching address

Let's start compiling only injector.cpp and textexe.cpp, the evildll.cpp file need an additional step to work.
![Alt text](Pasted image 20240204005950.png)

Note: I recommend using x64 architecture and release in the compiler option.

First of all we need to to point out the function's address to make a hook. For that step Ghidra can help us to disassemble textexe.exe and find greeting address.

![Alt text](Pasted image 20240203234558.png)

After you open exe in Ghidra, you can see a lot of strange assembler code, and a good question it's, how to start our finding?

![Alt Text](https://i.kym-cdn.com/photos/images/original/001/142/233/897.gif)

Don't panic. One tip it's execute our exe and find some useful string in the output.

![Alt text](Pasted image 20240203234533.png)

The string **Hello world** it's our starting point.

![Alt text](Pasted image 20240203232940.png)

We can use the **Find String** functionality to get the location of this string.

![Alt text](Pasted image 20240203233021.png)

And clicking the string we can find our function using the decompiler option, that look very similar of the greeting function in the source code.

An important information is the function address value: 140001000
It's because it's a 64 bytes architecture.

![Alt text](https://www.icegif.com/wp-content/uploads/pikachu-crying-icegif.gif)

Despite this, we can't use this address, because it's not a runtime address, or in other words that code don't running in memory yet.

With x64dbg it's possible to get the address in runtime to our hook.

![Alt text](Pasted image 20240203231044.png)

Opening testexe.exe and running in **Run to user code** , we can see a lof of assembler code, similar to Ghidra.

![Alt text](Pasted image 20240203231120.png)

Similar to Ghidra, we can start finding the **Hello world** string. 

![Alt text](Pasted image 20240203231856.png)

And if we take a look at the code, it's very similar of ghidra assembler code.

The address it's:  00007FF621251000
In hex format: 0x00007FF621251000

![Alt text](Pasted image 20240203231812.png)

Another way to get the address or validate it's using the **Symbols** option and find the **greeting function**.

![Alt text](Pasted image 20240203230111.png)

If you already execute the testexe with an incorrect key, you can receive the function.
I know, it's a cheat, but with that we can validate the address.
The main topic is the process of getting the address and the useful tools for that purpose.

Having the function address, now it's the time to compile our evildll.cpp file.

![Alt text](Pasted image 20240204002522.png)

You need to update the address in the code

![Alt text](Pasted image 20240203230307.png)

## Injecting DLL

Now, run the injector with the values.

```cmd
injector.exe testexe.exe evildll.dll
```

And if you don't receive an error or a different output, that means your dll was injected and the hook it's running.

![Alt text](Pasted image 20240203230234.png)

Note: If you want to know the name of the testexe.exe process, you can check the **task administrator**.

![Alt text](Pasted image 20240203230325.png)

![Alt text](Pasted image 20240203230340.png)

And that all, testing in your testexe running process you will receive different values.

![Alt Text](https://i.makeagif.com/media/5-08-2014/4Zsl7h.gif)

## Conclusions

* Make a hook it's very easy, the bad part is searching the address of the function that you want to change it's behaviour.
* In this example I take some facilities, such as using **declspec(noinline)** and printing the function address. The noinline directive it's the most important, because without that, our work will be more difficult. According to chatgpt description is a Microsoft-specific attribute used to instruct the compiler not to perform function inlining optimization. For that reason our function was separate of main function.
* It's possible to use other debuggers like Windbg or Ghidra dbg.
