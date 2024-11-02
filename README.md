<div align="left" style="position: relative;">
<img src="https://github.com/user-attachments/assets/ebcd2c79-ee57-4fcb-8e02-dafbed184c5f" align="right" width="30%" style="margin: -20px 0 0 20px;">
<h1>MadInjector GUI</h1>
</p>
<p align="left">
	<img src="https://img.shields.io/github/license/eli64s/readme-ai?style=default&logo=opensourceinitiative&logoColor=white&color=ce00ff" alt="license">
</p>
  
</p>
<p align="left">

</p>
</div>
<br clear="right">

##  Table of Contents

I. [ Overview](#-overview)
II. [ Features](#-features)
III. [ Project Structure](#-getting-started)
IV. [ Credits](#-Credits)

---

##  Overview

<text>❯ This repository only contains the Injector code which has nothing to do with my MadInjector GUI which can be found here https://github.com/rickmad11/MadInjector-GUI. 

Also note that this repository does not contain any binaries or precompiled files, these can be found in my GUI release.

The library was intended for me to learn new stuff about Windows and how User Mode Injection works in more depth. The initial idea was to provide a simple Library/Reference for myself. It was never meant to replace or be better than other already existing Injectors, this injector library is in no way any better than the current existing ones, in fact mine is less stable and does not support many OS versions.

This project is meant to be a resource for those who want to learn more about user mode injection. I tried to keep stuff simple so it is easier to find and quickly look for an injection method of choice without having the need to understand the entire code base, this of course also came with the downside of me making a lot of bad code decisions. Looking at the project now after finishing it, I would say I'm ok with the results after all, I reached what I wanted, which was learning new things.

The code contains comments explaining certain things that I thought were important to understand the specific injection method. You could view this project as some sort of tutorial. However, keep in mind that not everything I have written there is correct.

The injector is focused on x64 targets. However, some basic features do work on x86 as well.

Also note this was only tested on Windows 11 Version 23H2 Build 22631.4317 however, it should also work with older versions as well as with Windows 10, but I cannot guarantee every feature working on it.

If you are someone working with Visual Studio solution explorer filters, I have to disappoint you since I did not use any of these and used the folders instead. So make sure you click Show All Files in the Solution Explorer.

If you encounter any TODO comments, you can ignore them. I planned to add more features and rework some code. However, I see no reason for me to continue working on this project anymore since I have gotten to the point where I learned enough about Windows User Mode Injections. I still have other stuff to learn more about.

Maybe I will continue working a bit on this project, but for now I am planning not to do so.

Also, I have to apologize for my error handling in this entire project in advance since it's basically nonexistent.

This is the GUI version of my injector, it shows most features. Listing all of them would take too much time.

All Thread Pool Injection Methods work. However, each comes with some flaws. Some take longer than others, and if you check out my code, you will notice that I came up with the worst possible solution to not make the target process crash.

<img src="https://github.com/user-attachments/assets/3199c267-e470-4582-97df-293885416847" style="margin: -80px 0 0 80px;">

---

##  Features

<text>❯ 
**Supported Execution Methods:**

❯ CreateRemoteThread x64/x86

❯ NtCreateThreadEx x64/x86

        -> Hide From Debugger

        -> Skip Thread Attach

        -> Start Address Spoof

❯ SetWindowsHook x64/x86

❯ ThreadHijacking x64/x86

❯ QueueUserAPC x64/x86

❯ KernelCallbackTable x64/x86

❯ VectoredExceptionHandler x64

❯ ThreadPool x64

        -> WorkerThreadEntry
        
        -> WorkInsert
        
        -> JobInsert
        
        -> Direct
        
        -> Wait
        
        -> Timer
        
        -> Io
        
        -> Alpc

❯ InstrumentationCallback x64 

❯ TLS Callback x64 


**Supported Injection Methods:**

❯ LoadLibrary

❯ LdrLoadDll

❯ LdrpLoadDll

❯ LdrpLoadDllInternal

❯ Manual Map x64 -> please view the picture for all of the options

**Additional Features:**

-> Handle Hijacker x64 -> System Process only (this is a optional flag)

-> Unlink Module Button x64 -> can be any module all the Injector needs is the Path to the already loaded Module

-> Unlink Module CheckBox x64 -> This unlinks the Module right after execution the Dll in the target

-> Unload Mapped Dll x64 -> has some flaws but only works if injected with my Manual Mapper

-> Save/Load/Reset Settings

##  Getting Started

###  Prerequisites

-**Windows 10 or Greater**

-**Visual Studio 2022**

-**c++20 support preferably C++23**

In case you want to use c++20 you will need to make minor changes iirc std::basic_string::contains is the only thing that needs to be changed. 

-**admin privileges since some features require it**

-**following settings:**

<img src="https://github.com/user-attachments/assets/c89a72b7-2c14-499c-aee4-1003a1865e9c" style="margin: -40px 0 0 40px;">
<img src="https://github.com/user-attachments/assets/bf58dc96-b60b-4a27-a01a-1ae911b45752" style="margin: -40px 0 0 40px;">
<img src="https://github.com/user-attachments/assets/3735e613-54e7-4b30-872f-6c56eb85e719" style="margin: -40px 0 0 40px;">
<img src="https://github.com/user-attachments/assets/4fac895f-8720-4ec5-ba76-a3b9904f7695" style="margin: -40px 0 0 40px;">
<img src="https://github.com/user-attachments/assets/fd1dbc82-c712-4fc0-b948-1126740221e6" style="margin: -40px 0 0 40px;">

###  Installation

**Simply Download the source and compile it**

Using the library is quite simple. All you have to do is invoke the wMadInjector or MadInjector functions, both of which are exported. The corresponding header file is called MadInjector.hpp and can be found inside the includes folder.
The DLL can be used just like any other DLL.

One example

<img src="https://github.com/user-attachments/assets/fcf92995-ed92-4f23-91dc-d6e0edb2a992" style="margin: -40px 0 0 40px;">

Please note, always include the windows header before you include my header.


##  License
This project is protected under the [MIT-LICENSE]([https://choosealicense.com/licenses](https://choosealicense.com/licenses/mit/)) License. For more details, refer to the [LICENSE]([https://choosealicense.com/licenses/](https://github.com/rickmad11/MadInjector-GUI/blob/master/LICENSE)) file.

## Credits
**ThreadPool Injection :** 

https://www.safebreach.com/blog/process-injection-using-windows-thread-pools/

https://urien.gitbook.io/diago-lima/a-deep-dive-into-exploiting-windows-thread-pools

https://www.youtube.com/watch?v=AvBO4f7blew

**General Projects/Websites that made this Project possible in the first place**

https://github.com/guided-hacking/GuidedHacking-Injector

https://www.debuginfo.com/articles/debuginfomatch.html

https://ntdoc.m417z.com/

https://github.com/paskalian/WID_LoadLibrary/tree/main

https://www.geoffchappell.com/

https://github.com/winsiderss/systeminformer

https://doxygen.reactos.org/

https://learn.microsoft.com/en-us/windows/

https://github.com/Deputation/instrumentation_callbacks


https://csandker.io/2022/05/24/Offensive-Windows-IPC-3-ALPC.html

---
