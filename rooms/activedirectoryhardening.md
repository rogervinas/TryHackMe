# [Active Directory Hardening](https://tryhackme.com/r/room/activedirectoryhardening)

## Task 2 Understanding General Active Directory Concepts

**What is the root domain in the attached AD machine?**

* Go to Server Manager > Local Server
* Check Domain

## Task 3 Securing Authentication Methods

**What is the default minimum password length (number of characters) in the attached VM?**

* Go to Group Policy Management
* Right click on Default Domain Policy > Edit
* Go to Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Password Policy
* Check Minimum password length

## Task 5 Microsoft Security Compliance Toolkit

**Find and open BaselineLocalInstall script in PowerShell editor - Can you find the flag?**

* Execute `powershell.exe`
* Execute:
  ```powershell
  cat "C:\Users\Administrator\Desktop\Scripts\Windows Server 2019 Security Baseline\Local_Script\BaselineLocalInstall.ps1" | `
  Select-String "THM"
  ```

**Find and open MergePolicyRule script (Policy Analyser) in PowerShell editor - Can you find the flag?**

* Execute `powershell.exe`
* Execute:
  ```powershell
  cat "C:\Users\Administrator\Desktop\Scripts\PolicyAnalyzer\PolicyAnalyzer_40\Merge-PolicyRules.ps1" | `
  Select-String "THM"
  ```
