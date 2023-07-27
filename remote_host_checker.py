import subprocess
import argparse
import pandas as pd

from pypsexec.client import Client
from smbprotocol.exceptions import BadNetworkName, CannotDelete


def get_connection(ip: list) -> None:
    """
    Establish a connection to a remote Windows machine and run a PowerShell command.

    This function takes a list as an argument, which should contain the IP address, username,
    and password for the remote machine. It uses these credentials to connect to the machine
    and run a PowerShell command that exports the security policy to a file.

    If the connection fails or an error occurs while running the command, the function will
    print an error message and return None.

    :param ip: A list containing the IP address, username, and password for the remote machine.
    :return: None
    """

    try:

        win_client = Client(
            ip[0], username=ip[1], password=ip[2])
        win_client.connect()
        win_client.create_service()

        arg = r"if (!(Test-Path -Path C:\temp )) { New-Item -ItemType directory -Path C:\temp };secedit /export /cfg C:\temp\secpol.cfg /areas SECURITYPOLICY"
        win_client.run_executable(
            "powershell.exe", arguments=arg)

        # arg = " \"Get-ItemPropertyValue -Path 'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion' -Name 'ProductName'\""

        # stdout, stderr, rc = win_client.run_executable(
        #     "powershell.exe", arguments=arg)
        # output = stdout.decode("utf-8").replace('\r\n', '')
        # print(output)

    finally:
        win_client.remove_service()
        win_client.disconnect()


def check_connection(ip: list) -> bool:
    """
    Try to establish a connection to a remote Windows machine multiple times.

    This function takes a list as an argument, which should contain the IP address, username,
    and password for the remote machine. It attempts to connect to the machine using the
    get_connection function. If the connection fails, it will print an error message and try
    again, up to a maximum of 5 attempts.

    After 5 failed attempts, or if a connection is successfully established, the function
    will return a boolean indicating whether the connection was successful.

    :param ip: A list containing the IP address, username, and password for the remote machine.
    :return: True if a connection was successfully established, False otherwise.
    """
    result = False
    error_msg = ""
    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            get_connection(ip)
            result = True
            break
        except AttributeError:
            error_msg = "Please check IP address and Firewall setting: Ensure 'Windows Firewall: Allow inbound file and printer sharing exception' is 'Enabled' and allow incoming messages from the scanner machine's IP address."
            print(f"{ip[0]} | {error_msg}")
        except CannotDelete:
            error_msg = "Please check IP address and Firewall setting: Ensure 'Prohibit use of Internet connection firewall on your DNS domain' is either 'Disabled' or 'Not Configured'."
            print(f"{ip[0]} | {error_msg}")
        except TypeError:
            error_msg = "Please ensure the User Account Control is off."
            print(f"{ip[0]} | {error_msg}")
        except BadNetworkName:
            error_msg = "Please ensure the administrative shares is enabled."
            print(f"{ip[0]} | {error_msg}")

        print(f"Tried {attempt+1} times")

    return result, error_msg


def check_admin_shares():
    # Note: This is a simplistic check and might not cover all configurations.
    # It only checks if the shares are present, not if they're correctly configured.
    try:
        output = subprocess.check_output("net share", shell=True).decode()
        return "ADMIN$" in output and "C$" in output
    except Exception as e:
        print(f"Failed to check admin shares: {e}")
        return False


def configurations(config_fname: str) -> list:
    """
    This function takes the filename of an Excel file as an argument. The file should contain 
    a worksheet with columns for 'IP Address', 'Username', 'Password', and 'Windows Version'. 

    The function reads these columns and creates a list of lists, where each inner list 
    represents a row from the worksheet and contains the IP address, username, password, 
    and Windows version from that row.

    :param config_fname: A string containing the filename of an Excel file.
    :return: A list of lists, where each inner list contains the IP address, username, 
             password, and Windows version for a single row of the worksheet.
    """

    config_file = pd.ExcelFile(config_fname)

    configs = config_file.parse(sheet_name=0)

    ip_list = []

    ips = configs['IP Address'].values
    usernames = configs['Username'].values
    passwords = configs['Password'].values
    versions = configs['Windows Version'].values

    for idx, val in enumerate(ips):
        ip = [ips[idx], usernames[idx],
              passwords[idx], versions[idx]]

        ip_list.append(ip)

    return ip_list


'''
This is the entry point of the script. The function reads from a configuration file specified
by the user when running the script, checks the remote host requirements for each host specified 
in the configuration file, and writes the results to "remote_test_result.txt".

The configuration file is specified via a command-line argument --config when running the script.
Each row of the configuration file should contain information for a single host.

The function iterates through each host, checks the remote host requirements using the 
check_connection function, and records the results. If all requirements are met for a host, 
the function prints and records a success message. If not, it prints and records the error message.

At the end of the script, the function writes all the results to "remote_test_result.txt" in the 
same directory where the script is located.

Usage: 
    python remote_host_checker.py --config /path/to/config/file

:param --config: A string containing the path to the configuration file.
:return: None
'''
if __name__ == "__main__":

    my_parser = argparse.ArgumentParser(
        description='Remote host requirement checker')

    # Add the arguments
    my_parser.add_argument('--config',
                           type=str,
                           required=True,
                           help='The path of configuration file')

    # Execute parse_args()
    args = my_parser.parse_args()

    print('Configuration file:', args.config)

    # read configurations
    ip_list = configurations(args.config)

    output_log = ""
    for ip in ip_list:
        test_reuslt = check_connection(ip)
        if test_reuslt[0]:
            print(f"{ip[0]} | Remote host requirement fulfilled.")
            output_log += ip[0] + " | Remote host requirement fulfilled.\n"

        else:
            print(test_reuslt[1])
            output_log += ip[0] + " | " + test_reuslt[1] + "\n"

    with open("remote_test_result.txt", 'w') as f:
        f.write(output_log)

    print(f"Result saved in: remote_test_result.txt")
