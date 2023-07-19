# CIS Auditor Windows

This project provides a customizable, multiprocessing, remote security auditing program. It enables users to adapt [CIS benchmark audit policies](https://www.cisecurity.org/cis-benchmarks) to their unique needs, perform comprehensive security audits remotely, and leverage multiprocessing capabilities for efficient auditing. Aimed at overcoming the limitations of existing security audit solutions, this project offers an efficient, flexible, and scalable approach to system security auditing.

Supports Windows versions:
- [x] Windows 10 Enterprise
- [x] Windows 11 Enterprise
- [x] Windows Server 2016 MS/DC
- [x] Windows Server 2019 MS
- [x] Windows Server 2022 MS

## Addressing the Challenges

Existing security audit solutions often face the following limitations, which this project seeks to overcome:

1. **Inflexibility**: Solutions like Nessus do not offer the ability to tailor audit policies, imposing a "one-size-fits-all" approach. This can be inadequate for users with specific security requirements. Our project provides flexibility, allowing customized audit policies that can better address individual needs.

2. **Performance Bottlenecks**: Many current systems can be slow and often require post-processing, which lengthens auditing times and hinders efficiency. Our project addresses these bottlenecks by streamlining processes, offering improved speed and efficiency.

3. **Server Dependencies**: A common challenge with many audit solutions is their dependency on additional server resources, which adds to system complexity and potential scalability issues. Our project minimizes server dependencies, simplifying the system architecture and enhancing scalability.

## Features

This project introduces a customizable, multiprocessing, remote security audit program with the following key features:

1. **Customizable CIS Benchmark Audit Policies**: This solution allows users to customize the highly-regarded CIS benchmark audit policies according to their unique security needs. This ensures a more targeted and effective auditing process.

2. **Remote Assessment Capabilities**: The program's remote assessment functionality enables users to conduct comprehensive security audits from virtually any location, ensuring flexibility and ease of use.

3. **Multiprocessing Functionality**: By facilitating simultaneous execution of multiple processes, this program significantly speeds up the audit process. This feature not only saves valuable time but also ensures thoroughness and accuracy in the security audit.

## Project Workflow

This section describes the high-level workflow of the security audit program.
![image](https://github.com/Myohannn/CIS_Benchmark_Assessor_Win/assets/60417289/72330883-3713-4d90-8446-c6cbe0ce239c)


1. **Download Latest Audit File**: The program begins by downloading the latest CIS benchmark .audit file from [Nessus](https://www.tenable.com/audits/search?q=type%3A%28CIS%29+AND+display_name%3A%28L1%29+AND+plugin%3A%28Windows%29&sort=&page=1). This ensures that the program is always using the most up-to-date security benchmarks.

2. **Convert .audit file to Excel File**: Next, the program converts the .audit file into an Excel file. This allows for easier manipulation and customization of the audit policies.

3. **Customize Audit Policies**: With the benchmarks in Excel format, you can easily customize the audit policies to suit your specific needs. The program can then read this customized set of audit policies when performing the security audit.

4. **Configure Server Details**: After customizing the audit policies, you'll need to provide the program with the details of the servers you want to audit. This includes server addresses, login credentials, and select the os version of the target server.

5. **Run the Program**: With the audit policies and server details configured, you're ready to run the program. The program will connect to the specified servers and perform the security audit based on your customized policies.

6. **Review Results**: After the program has completed the audit, you can review the results. These will tell you whether each audit check passed or failed, and provide you with any relevant information about potential security issues.


***
## Powershell commands

REGISTRY_SETTING / BANNER_CHECK / REG_CHECK

    ``` powershell
    Get-ItemPropertyValue -Path '{reg_key}' -Name '{reg_item}'
    
    e.g., Get-ItemPropertyValue -Path 'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion' -Name 'ProductName'
    ```
    
PASSWORD_POLICY / ANONYMOUS_SID_SETTING
      
    ``` powershell
    if (!(Test-Path -Path C:\temp )) { New-Item -ItemType directory -Path C:\temp }
    secedit /export /cfg C:\temp\secpol.cfg /areas SECURITYPOLICY
    $secpol = Get-Content -Path C:\temp\secpol.cfg
    $secpol | Select-String -Pattern '{subcategory}'
    
    e.g., $secpol | Select-String -Pattern "PasswordHistory"
    ```
    
USER_RIGHTS_POLICY

    ``` powershell
    if (!(Test-Path -Path C:\temp )) { New-Item -ItemType directory -Path C:\temp }
    secedit /export /cfg C:\temp\secpol.cfg /areas user_rights
    $secpol = Get-Content -Path C:\temp\secpol.cfg
    $secpol | Select-String -Pattern "SeCreateSymbolicLinkPrivilege"
    
    e.g., $secpol | Select-String -Pattern "SeNetworkLogonRight"
    ```
    
LOCKOUT_POLICY

    ```powershell
    net accounts
    net accounts | Select-String -Pattern "{subcategory}"
    ```
    
CHECK_ACCOUNT

    ```powershell
    net user guest
    net user administrator
    net user administrator | select-string -pattern "{subcategory}"
    ```
    
AUDIT_POLICY_SUBCATEGORY
      
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
1. 
