---
layout: post
title: "How to hook a exe function"
img_path: /assets/img/posts/how-to-hook-a-exe-function-address/
---

<script
  type="text/javascript"
  src="https://cdn.jsdelivr.net/npm/gist-embed@1.0.4/dist/gist-embed.min.js"
></script>

# How to hook a exe function address

Hello everyone, this it's my first post about reverse engineering.

Today, I make a easy and understanding tutorial about how to hook a specific function of a executable, using its address to change the result of a string. Don't worry if you are a newbie (me too), I'm going to explain all the steps to make your first hook.

![Alt text](Pasted image 20240204003959.png)
## Configuring your local laboratory

In this example I'm using some Reversing tools, such as:
- Ghidra
- x64dbg
- visual studio (compiler)

Also, I'm sharing the source code if you want to try yourself.

Source code exe target:

{% raw %}
<code data-gist-id="589536c7d16cec7f33c0735c4752c595" data-gist-line="X-X" data-gist-hide-footer="true"></code>
{% endraw %}

Source code dll to inject:
https://gist.github.com/AdrianN17/7f5ea07477b4ca0cffac21749467ce4f

Source code injector
https://gist.github.com/AdrianN17/941dce4fc9b73305e822485cbbc54a19

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

Note: I recommend configurate compiler option to x64 arquitecture and release.

First of all we need to pointing out in get the function's address to make a hook. For that step Ghidra can help us to dissasemble textexe.exe and find greeting address.

![Alt text](Pasted image 20240203234558.png)

After you open exe in Ghidra, you can see a lot of strange assembly code, and a good question it's, how to start our finding?

![Alt Text](https://i.kym-cdn.com/photos/images/original/001/142/233/897.gif)

Don't panic. One tip it's execute our exe and find some usefull string in output.

![Alt text](Pasted image 20240203234533.png)

The string **Hello world** it's our start point.

![Alt text](Pasted image 20240203232940.png)

We can use the **Find String** functionality to get the location of this string.

![Alt text](Pasted image 20240203233021.png)

And clicking the string we can find our function. Also we can check if is the correct function using the decompiler. It's very similar of the greeting function in source code.

An important information is the function address value: 140001000
It's because is a 64 bytes arquitecture.

![Alt text](https://www.icegif.com/wp-content/uploads/pikachu-crying-icegif.gif)

Despite this, we can't use this address, because it's not a runtime address, or in other words that code don't running in memory yet.

With x64dbg it's possible to get the address in runtime to our hook.

![Alt text](Pasted image 20240203231044.png)

Opening testexe.exe and running in **Run to user code** , we can see a lof of assembly code, similar to Ghidra.

![Alt text](Pasted image 20240203231120.png)

Similar to Ghidra, we can start finding the **Hello world** string. 

![Alt text](Pasted image 20240203231856.png)

And if we take a look at the code, it's very similar of ghidra assemby.

The address it's:  00007FF621251000
In hex format: 0x00007FF621251000

![Alt text](Pasted image 20240203231812.png)

Another way to get the address or validate it's using **Symbols** option and find the **greeting function**.

![Alt text](Pasted image 20240203230111.png)

If you already execute the testexe with an incorrect key, you can receive the function.
I know, it's a cheat, but with that we can validate the address.
The main topic it's know the process of get the address and the usefull tools for that purpose.

Having the function address, now it's the time to compile our evildll.cpp file.

![Alt text](Pasted image 20240204002522.png)

You need to update the address in the code

![Alt text](Pasted image 20240203230307.png)

## Injecting DLL

Now, run the injector with the values.

```cmd
injector.exe testexe.exe evildll.dll
```

And if you don't receive error or a different output, that means your dll was injected and the hook it's running.

![Alt text](Pasted image 20240203230234.png)

Note: If you want to know the name of the  testexe.exe process, you can check the **task administrator**.

![Alt text](Pasted image 20240203230325.png)

![Alt text](Pasted image 20240203230340.png)

And that all, testing in your testexe running proccess you will receive different values.

![Alt Text](https://i.makeagif.com/media/5-08-2014/4Zsl7h.gif)

## Conclusions

* Make a hook it's very easy, the bad part is search the address of the function that you want to change it's behaviour.
* In this example I take some facilities, such as using **declspec(noinline)** and printing the function address. The noinline directive it's the most important, because without that, our work will be more difficult.  According to chatgpt description is a Microsoft-specific attribute used to instruct the compiler not to perform function inlining optimization. For that reason our function was separate of main function.
* It's possible to use others debuggers like windbg or Ghidra dbg.
