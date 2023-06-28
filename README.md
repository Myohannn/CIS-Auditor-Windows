# CIS Benchmark Assessor

### Available version:
- [x] Windows 10

## Powershell commands

- [x] REGISTRY_SETTING / BANNER_CHECK / REG_CHECK

    ``` powershell
    Get-ItemPropertyValue -Path '{reg_key}' -Name '{reg_item}'
    
    e.g., Get-ItemPropertyValue -Path 'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion' -Name 'ProductName'
    ```
    
- [ ]  PASSWORD_POLICY / ANONYMOUS_SID_SETTING
      
    ``` powershell
    if (!(Test-Path -Path C:\temp )) { New-Item -ItemType directory -Path C:\temp }
    secedit /export /cfg C:\temp\secpol.cfg /areas SECURITYPOLICY
    $secpol = Get-Content -Path C:\temp\secpol.cfg
    $secpol | Select-String -Pattern '{subcategory}'
    
    e.g., $secpol | Select-String -Pattern "PasswordHistory"
    ```
    
- [ ]  USER_RIGHTS_POLICY

    ``` powershell
    if (!(Test-Path -Path C:\temp )) { New-Item -ItemType directory -Path C:\temp }
    secedit /export /cfg C:\temp\secpol.cfg /areas user_rights
    $secpol = Get-Content -Path C:\temp\secpol.cfg
    $secpol | Select-String -Pattern "SeCreateSymbolicLinkPrivilege"
    
    e.g., $secpol | Select-String -Pattern "SeNetworkLogonRight"
    ```
    
- [ ]  LOCKOUT_POLICY

    ```powershell
    net account
    ```
    
- [ ]  CHECK_ACCOUNT

    ```powershell
    net user guest
    net useradministrator
    ```
    
- [ ]  AUDIT_POLICY_SUBCATEGORY
      
    ```powershell
    auditpol /get /subcategory:'{subcategory}'

    e.g., auditpol /get /subcategory:"Special Logon"
    ```

***
## SETUP -- Windows configuration

### (Local accounts only) User Account Control (UAC)
Disable Windows User Account Control (UAC), or you must change a specific registry setting to allow connection. To disable UAC, open the Control Panel, select User Accounts, and set Turn User Account Control to Off.

`Recommend:` Alternatively, instead of disabling UAC, you can add a new registry DWORD named LocalAccountTokenFilterPolicy and setting its value to 1. Create this key in the following registry: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\LocalAccountTokenFilterPolicy. 

### Host Firewall
Using the Run prompt, run gpedit.msc and enable Group Policy Object Editor. Navigate to Local Computer Policy > Administrative Templates > Network > Network Connections > Windows Firewall > Standard Profile > Windows Firewall: Allow inbound file and printer exception and enable it.

While in the Group Policy Object Editor, navigate to Local Computer Policy > Administrative Templates > Network > Network Connections > Prohibit use of Internet connection firewall on your DNS domain. Set this option to either Disabled or Not Configured.

Open any host firewalls to allow connections from local to File and Printer Sharing on TCP ports `139` and `445`.

### Remote Registry
Enable the Remote Registry. You can enable it for a one-time audit, or leave it enabled permanently if you perform frequent audits.

### Administrative Shares
Enable administrative shares (IP$, ADMIN$, C$). Make sure you have the administrator access.

Note: Windows 10 disables ADMIN$ by default. For all other operating systems, the three administrative shares are enabled by default and can cause other issues if disabled. For more information, see http://support.microsoft.com/kb/842715/en-us.

## Prepare audit file -- conversion.py
1. PASSWORD_POLICY (automated):
    1. Manually modify all expexted values
        1. Enabled → 1, Disabled → 0
2. REGISTRY_SETTING (automated):
    1. 0 “Windows 10 is installed”: Modify value → actual windows version number e.g. Windows 10 Enterprise
    2. 2.3.7.9: ^(1|2|3)$ → 1 || 2 || 3
    3. 2.3.10.6: Value Data "" → Null
    4. 2.3.10.7: Remove " && "
    5. 2.3.10.8: Remove " && "
    6. 2.3.10.11: Value Data "" → Null
    7. 19.1.3.3: ^(900|[1-9][0-9]|[1-8][0-9]{2})$ → [0..900]
3. CHECK_ACCOUNT (automated): 
    1. 2.3.1.2: Disabled → No
    2. 2.3.1.4: \b[Aa]dmin(istrator)? → Administrator
4.  BANNER_CHECK (automated):
    1. 2.3.7.5 & 2.3.7.6: Manually modify expexted value to “Blank Message”
5. ANONYMOUS_SID_SETTING (automated): 
    1. 2.3.10.1 Manually modify expexted value: Disabled → 0
6. REG_CHECK (automated):
    1. 18.9.19.5 Replace "Value Data" and "Reg Key" 
  
***

## Remarks
1. Only suppots CIS Microsoft Windows 10 Enterprise Benchmark Level 1
2. Index 18.9.19.5 is hardcoded
