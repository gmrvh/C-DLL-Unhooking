# **NTDLL Unhooking PoC**  
### **Detecting and Restoring Hooked NTDLL Functions**  

**Author:** `Gamrah`  

---

## **🔹 Overview**  
This Proof-of-Concept (PoC) demonstrates how to detect and restore **hooked functions in `ntdll.dll`**, a common target for security monitoring tools like **EDRs** and **AVs**.  

It works by:
1. **Comparing function hashes** in the loaded (possibly hooked) `ntdll.dll` and a clean copy.
2. **Restoring the function's original bytes** if a hook is detected.
3. **Verifying the restoration** to ensure successful unhooking.  

---

## **🔹 Features**  
✅ **Detects hooks on `NtOpenProcess` and `NtQuerySystemInformation`**.  
✅ **Loads a clean `ntdll.dll` from disk for comparison**.  
✅ **Restores function prologue bytes if tampered with**.  
✅ **Uses `SHA256` hashing for integrity verification**.  
✅ **Provides real-time status updates on function restoration**.  

---

## **🔹 Installation**  

### **📌 Prerequisites**  
Ensure you have a **Windows machine** with a C# compiler installed.  

### **📌 Compile the Code**  
1. Open a terminal and navigate to the project directory.  
2. Compile the C# program using `csc.exe` (C# compiler):  
   ```powershell
   csc UnhookingPoC.cs
   ```  
3. Run the executable:  
   ```powershell
   .\UnhookingPoC.exe
   ```  

---

## **🔹 Usage**  
Simply execute the program. It will:
- Check for hooks on **NtOpenProcess** and **NtQuerySystemInformation**.
- If hooked, it will **restore the function bytes** from a clean copy.
- Verify the restoration by comparing SHA-256 hashes.

### **Sample Output**
```plaintext
=== NTDLL Unhooking PoC ===
[*] Checking NtOpenProcess: Before Hash: eadbf... | Clean Hash: a9f23...
[!] NtOpenProcess appears to be hooked! Restoring...
[*] After Hash: a9f23...
[+] NtOpenProcess successfully restored!
=== PoC Completed ===
```

