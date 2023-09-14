# CIS Auditor Windows

This project provides a customizable, multiprocessing, remote security auditing program. It enables users to adapt [CIS benchmark audit policies](https://www.cisecurity.org/cis-benchmarks) to their unique needs, perform comprehensive security audits remotely, and leverage multiprocessing capabilities for efficient auditing. Aimed at overcoming the limitations of existing security audit solutions, this project offers an efficient, flexible, and scalable approach to system security auditing.

Supports Windows versions:
- [x] Windows 10 Enterprise
- [x] Windows 11 Enterprise
- [x] Windows Server 2016 MS/DC
- [x] Windows Server 2019 MS/DC
- [x] Windows Server 2022 MS/DC

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

    
    Get-ItemPropertyValue -Path '{reg_key}' -Name '{reg_item}'
    
    e.g., Get-ItemPropertyValue -Path 'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion' -Name 'ProductName'
    
    
PASSWORD_POLICY / ANONYMOUS_SID_SETTING
      
    if (!(Test-Path -Path C:\temp )) { New-Item -ItemType directory -Path C:\temp }
    secedit /export /cfg C:\temp\secpol.cfg /areas SECURITYPOLICY
    $secpol = Get-Content -Path C:\temp\secpol.cfg
    $secpol | Select-String -Pattern '{subcategory}'
    
    e.g., $secpol | Select-String -Pattern "PasswordHistory"
    
USER_RIGHTS_POLICY

    if (!(Test-Path -Path C:\temp )) { New-Item -ItemType directory -Path C:\temp }
    secedit /export /cfg C:\temp\secpol.cfg /areas user_rights
    $secpol = Get-Content -Path C:\temp\secpol.cfg
    $secpol | Select-String -Pattern "right_type"
    
    e.g., $secpol | Select-String -Pattern "SeNetworkLogonRight"
    
LOCKOUT_POLICY

    net accounts
    net accounts | Select-String -Pattern "{subcategory}"
    
CHECK_ACCOUNT

    net user guest
    net user administrator
    net user administrator | select-string -pattern "{subcategory}"
    
AUDIT_POLICY_SUBCATEGORY
      
    auditpol /get /subcategory:'{subcategory}'

    e.g., auditpol /get /subcategory:"Special Logon"

WMI_POLICY
    
    (Get-WmiObject -Class Win32_ComputerSystem).DomainRole
    
***
## Program Directory Structure
```
Security Auditor Program (Python)/
│
├── config/
│ └── config.xlsx
│
├── script/
│ ├── CIS_Microsoft_Windows_Server_2016_Benchmark_v2.0.0_L1_MS.ps1
│ ├── CIS_Microsoft_Windows_Server_2019_Benchmark_v2.0.0_L1_DC.ps1
│ └── ……
│
├── src/
│ ├── Audit/
│ │ ├── CIS_Microsoft_Windows_Server_2016_Benchmark_v2.0.0_L1_MS.xlsx
│ │ ├── CIS_Microsoft_Windows_Server_2019_Benchmark_v2.0.0_L1_DC.xlsx
│ │ └── ……
│ │
│ └── CIS/
│ ├── CIS_Microsoft_Windows_Server_2016_Benchmark_v2.0.0_L1_MS.audit
│ ├── CIS_Microsoft_Windows_Server_2019_Benchmark_v2.0.0_L1_DC.audit
│ └── ……
│
├── utilities/
│ ├── init.py
│ ├── getAnonySID.py
│ ├── getAuditPolicy.py
│ ├── getBannerCheck.py
│ ├── getCheckAccount.py
│ ├── getLockoutPolicy.py
│ ├── getPwdPolicy.py
│ ├── getRegCheck.py
│ ├── getRegValue.py
│ ├── getUserRights.py
│ └── getWMIPolicy.py
│
├── audit_file_parser.py
├── local_audit_command_generator.py
├── local_audit_results_processor.py
├── remote_audit_executor.py
└── remote_host_checker.py
```

***
## Installation Guide

### Python Installation
-	Install Python version > 3.7
-   Install Python packages using pip
    - pip install bs4 lxml pandas argparse openpyxl regex pypsexec smbprotocol

## Remote Host Requirements (Remote version only)

### Enable Administrative Shares

#### Checking if Administrative Shares are Enabled

1. Open Command Prompt with administrative privileges. 
    - You can do this by searching for `cmd` in the Start menu, right-clicking on `Command Prompt`, and selecting `Run as administrator`.
2. Type `net share` and press Enter. This command will display all network shares that are currently available on the system.
3. Look at the output. If administrative shares are enabled, you should see entries like `C$`, `ADMIN$`, etc.

#### Enabling Administrative Shares

1. If you did not see the administrative shares in the output of the `net share` command, follow these steps to enable them:
2. Press `Win + R` to open the Run dialog, type `regedit`, and press Enter to open the Registry Editor. 
3. Navigate to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`.
4. Right-click in the right pane and select `New` → `DWORD (32-bit) Value`.
5. Name the new value:
   - `AutoShareWks` for workstations 
   - `AutoShareServer` for servers.
6. Double-click the new value and set its data to `1`.
7. Restart your computer to apply changes.

### Turn off User Account Control (UAC)

1. Press `Win + R`, type `regedit`, and press Enter to open the Registry Editor.
2. Navigate to `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`.
3. Right-click in the right pane, select `New` → `DWORD (32-bit) Value`, and name it `LocalAccountTokenFilterPolicy`.
4. Double-click the new value and set its data to `1`.
5. Restart your computer to apply changes.

### Configure Host Firewall 

#### Choice 1: Disable the firewall

- It's recommended to disable the firewall for simplicity, but this should only be done with caution due to potential security risks. If you choose this option, no further steps are necessary.

#### Choice 2: Adjust firewall settings

1. Press `Win+R` to open the Run dialog, type `gpedit.msc`, and press Enter to open the Group Policy Object Editor.
2. Navigate to `Local Computer Policy > Administrative Templates > Network > Network Connections`.
3. Locate the setting `Prohibit use of Internet connection firewall on your DNS domain`. Set this option to either `Disabled` or `Not Configured`.
4. Next, navigate to `Local Computer Policy > Computer Configuration > Administrative Templates > Network > Network Connections > Windows Defender Firewall > Standard Profile`.
5. Find the setting `Windows Firewall: Allow inbound file and printer sharing exception`, enable it, and set the option to allow messages specifically from the scanner machine's IP address.
![image](https://github.com/Myohannn/CIS-Auditor-Windows/assets/60417289/83e5e46d-2152-4df3-8867-4f1abdd61ceb)

***
## Running the Program

### Audit File Preparation

The audit process begins with the preparation of an audit file, which forms the basis for subsequent audit operations. Follow these steps to prepare your audit file:

1. **Download the latest CIS benchmark**: 
   - Download the Windows Level 1 .audit file from Nessus using the following URL:
     [Tenable Audits Search](https://www.tenable.com/audits/search?q=windows+L1+AND+type%3A%28CIS%29+AND+display_name%3A%28L1%29+AND+plugin%3A%28Windows%29&sort=&page=1)
     
   - Example file:
     [CIS MS Windows 10 Enterprise Level 1 v2.0.0](https://www.tenable.com/audits/CIS_MS_Windows_10_Enterprise_Level_1_v2.0.0)

     ![image](https://github.com/Myohannn/CIS-Auditor-Windows/assets/60417289/39481189-65ae-4955-80fd-0d386ef02956)

2. **Run the parser**:
   - Run the `audit_file_parser.py` script from the command line, passing the path of the .audit file as an argument.
     ```
     python audit_file_parser.py -audit /path/to/audit/file
     ```

3. **Review the Output**:
   - Upon successful completion of the script, you'll find an Excel file in the `/src/Audit` directory. This file, which will have the same name as the input .audit file, contains the results of the script's operations.

4. **Customize the Excel File**: 
   - Customize the Excel file according to your requirements. This custom file will serve as the input for the audit process. Save any changes you make.

### Running the Program Remotely

Conducting a remote audit with the Security Auditor Program involves the following steps:

1. **Prepare the Configuration File**:
   - Modify the `config.xlsx` file in the `config` directory. This file contains details for the security audit like IP address, username, password, and Windows version of the target system.
   
   - **Note**: Ensure the provided account has administrator privileges. Maintain consistency by selecting the same Windows version for each audit.

     ![image](https://github.com/Myohannn/CIS-Auditor-Windows/assets/60417289/e31c7f32-3ad2-4268-9e11-64500f7f48d7)


2. **Check the Remote Host**:
   - Run the `remote_host_checker.py` script from the command line:
     ```
     python remote_host_checker.py -config config.xlsx
     ```
   - Review the script's output to check if administrative shares are enabled, UAC is off, and the firewall is configured correctly.

3. **Execute Remote Audit**:
   - If the remote hosts fulfill requirements, run the `remote_audit_executor.py` script:
     ```
     python remote_audit_executor.py -config config.xlsx -output output.xlsx
     ```
   - After execution, review the findings in the specified output file (e.g., `output.xlsx`).

### Running the Program Locally

For a local audit:

1. **Generate Audit Commands**:
   - Run the `local_audit_command_generator.py` script:
     ```
     python local_audit_command_generator.py -audit audit_file.xlsx
     ```

2. **Execute PowerShell Script**:
   - Copy the generated PowerShell script to the target host and run it in PowerShell as Administrator. Redirect the output and errors:
     ```
     ./script_name.ps1 > audit_result.txt 2> debug_log.txt
     ```
   - For permission errors:
     ```
     Set-ExecutionPolicy Unrestricted
     ```

3. **Process Audit Results**:
   - Return the output file to the local host and process the results:
     ```
     python local_audit_results_processor.py -audit audit_file.xlsx -ps_result audit_result.txt -output output.xlsx
     ```
   - Review the results in the specified output file (e.g., `output.xlsx`).

**Note**: For troubleshooting, refer to the "Common Troubleshoots" section of this manual.

***

## Common Troubleshoots

The following guidelines provide solutions to some common issues that you might encounter while running the remote audit script. These suggestions are designed to assist in resolving issues in a systematic way.

### Script fails to run
- Ensure Python is installed and properly configured on your machine.
- Make sure all required Python packages are installed. These might include `pandas`, `openpyxl`, and any others imported in the script.

### Script cannot read the configuration or audit files
- Confirm the paths to the files are correct.
- Verify the files are formatted correctly.
- Ensure the script has read permissions for these files.
- Ensure all target systems specified in a single Excel configuration file share the same Windows version.

### Script cannot write the output file
- Verify the script has write permissions in the directory it's trying to write the output file to.
- If the file is already open, close it before running the script.

### Script fails to connect to the target systems
- Make sure the target systems are up and running.
- Check the network connection between your machine and the target systems.
- Confirm the IP addresses, usernames, and passwords in the configuration file are correct.
- Ensure the account used is an administrator account (for remote access).
- Verify the registry and firewall settings.
- Common error messages:
  - "`[WinError 10060] A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond.`"
  - "`smbprotocol.exceptions.LogonFailure: Received unexpected status from the server: The attempted logon is invalid. This is either due to a bad username or authentication information.`"
  - "`AttributeError: 'NoneType' object has no attribute 'open_service_w'.`"

### Script returns incorrect or unexpected audit results
- Check the audit commands in the Excel file and in the `gen_ps_args` function.
- Make sure the target systems have the required features enabled and permissions set to allow the script to run its tasks.

### Script runs slowly or hangs
- Consider reducing the number of target systems or the number of audit tasks.
- Monitor the system resources on the machine running the script. It may need more memory or CPU power to handle the tasks.



