import pandas as pd
import logging
import argparse


# Setting up logging for the script. This will log debug messages to a file called 'mylog.log'.
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

handler = logging.FileHandler('mylog.log', mode='w')
handler.setLevel(logging.DEBUG)

formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)


def gen_ps_args(data_dict: dict) -> dict:
    '''
    This function generates PowerShell commands based on the provided audit type.

    The function takes a dictionary where each key is an audit type and each value is a DataFrame 
    containing the audit data for that type. The function iterates over each audit type and generates 
    the appropriate PowerShell commands to audit that type. The commands are saved in a new dictionary 
    where each key is an audit type and each value is a string of PowerShell commands.

    Note: For some audit types, the conditions for generating commands are hardcoded. This may need 
    to be updated in the future if the audit requirements change.

    :param data_dict: A dictionary where each key is an audit type and each value is a DataFrame 
                      containing the audit data for that type.
    :return: A dictionary where each key is an audit type and each value is a string of PowerShell 
             commands to audit that type.
    '''

    ps_args_dict = {}

    for key, df in data_dict.items():

        checklist_values = df['Checklist'].values
        description_values = df['Description'].values
        reg_key_values = df['Reg Key'].values
        reg_item_values = df['Reg Item'].values
        subcategory_values = df['Audit Policy Subcategory'].values
        right_type_values = df['Right type'].values

        if key == "REGISTRY_SETTING":

            reg_value_args = []

            for idx, val in enumerate(checklist_values):
                # generate command list for getting regristry value
                reg_key = str(reg_key_values[idx])
                reg_item = str(reg_item_values[idx])

                if reg_key.startswith("HKLM"):
                    reg_key = reg_key.replace("HKLM", "HKLM:")
                elif reg_key.startswith("HKU"):
                    reg_key = reg_key.replace("HKU", "HKU:")

                arg = f"Write-Output '====';\nGet-ItemPropertyValue -Path '{reg_key}' -Name '{reg_item}'"
                reg_value_args.append(arg)

            ps_args_dict[key] = ';\n'.join(reg_value_args)

        elif key == "PASSWORD_POLICY":

            pwd_policy_args = []

            for idx, val in enumerate(checklist_values):
                # if val == 1:

                # generate command list for getting password policy value
                description = str(description_values[idx])

                if "Enforce password history" in description:
                    subcategory = 'PasswordHistorySize ='

                elif "Maximum password age" in description:
                    subcategory = 'MaximumPasswordAge ='

                elif "Minimum password age" in description:
                    subcategory = 'MinimumPasswordAge ='

                elif "Minimum password length" in description:
                    subcategory = 'MinimumPasswordLength ='

                elif "complexity requirements" in description:
                    subcategory = 'PasswordComplexity ='

                elif "reversible encryption" in description:
                    subcategory = 'ClearTextPassword ='

                elif "Administrator account lockout" in description:
                    subcategory = ''

                elif "Force logoff when logon hours expire" in description:
                    subcategory = 'ForceLogoffWhenHourExpire ='

                else:
                    pwd_policy_args.append("\n")

                arg = f"Write-Output '====';\nGet-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern '{subcategory}'"

                pwd_policy_args.append(arg)

            ps_args_dict[key] = ';\n'.join(pwd_policy_args)

        elif key == "LOCKOUT_POLICY":

            lockout_policy_args = []
            for idx, val in enumerate(checklist_values):
                # if val == 1:

                # generate command list for getting lockout policy value
                description = str(description_values[idx])

                if "Account lockout duration" in description:
                    lockout_policy_args.append(
                        "Write-Output '====';\nnet accounts | select-string -pattern 'Lockout duration'")

                elif "Account lockout threshold" in description:
                    lockout_policy_args.append(
                        "Write-Output '====';\nnet accounts | select-string -pattern 'Lockout threshold'")

                elif "Reset account lockout counter" in description:
                    lockout_policy_args.append(
                        "Write-Output '====';\nnet accounts | select-string -pattern 'Lockout observation window'")
                else:
                    lockout_policy_args.append("Write-Output '====';\n")

            ps_args_dict[key] = ';\n'.join(lockout_policy_args)

        elif key == "USER_RIGHTS_POLICY":

            user_rights_args = []

            for idx, val in enumerate(checklist_values):

                # if val == 1:
                right_type = str(right_type_values[idx])

                arg = f"Write-Output '====';\nGet-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern '{right_type}'"

                user_rights_args.append(arg)

            ps_args_dict[key] = ';\n'.join(user_rights_args)

        elif key == "CHECK_ACCOUNT":
            check_account_args = []
            for idx, val in enumerate(checklist_values):
                # if val == 1:

                # generate command list for getting check account value
                description = str(description_values[idx])

                if "Guest account status" in description:
                    check_account_args.append(
                        "Write-Output '====';\nnet user guest | select-string -pattern 'Account active'")

                elif "Administrator account status" in description:
                    check_account_args.append(
                        "Write-Output '====';\nnet user administrator | select-string -pattern 'Account active'")

                elif "Rename administrator account" in description:
                    check_account_args.append(
                        "Write-Output '===='\nnet user administrator | select-string -pattern 'User name'")

                elif "Rename guest account" in description:
                    check_account_args.append(
                        "Write-Output '====';\nnet user guest | select-string -pattern 'User name'")
                else:
                    check_account_args.append("Write-Output '====';\n")

            ps_args_dict[key] = ';\n'.join(check_account_args)

        elif key == "BANNER_CHECK":
            banner_check_args = []

            for idx, val in enumerate(checklist_values):
                # if val == 1:
                # generate command list for getting regristry value
                reg_key = str(reg_key_values[idx])
                reg_item = str(reg_item_values[idx])

                if reg_key.startswith("HKLM"):
                    reg_key = reg_key.replace("HKLM", "HKLM:")
                elif reg_key.startswith("HKU"):
                    reg_key = reg_key.replace("HKU", "HKU:")

                arg = f"Write-Output '====';\nGet-ItemPropertyValue -Path '{reg_key}' -Name '{reg_item}'"
                banner_check_args.append(arg)

            ps_args_dict[key] = ';\n'.join(banner_check_args)

        elif key == "ANONYMOUS_SID_SETTING":

            anonymous_sid_args = []
            anonymous_sid_args_list = []

            for idx, val in enumerate(checklist_values):
                # if val == 1:

                # generate command list for getting password policy value
                description = str(description_values[idx])

                if "Allow anonymous SID/Name translation" in description:
                    subcategory = 'LSAAnonymousNameLookup ='

                arg = f"Write-Output '====';\nGet-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern '{subcategory}'"

                anonymous_sid_args.append(arg)

            anonymous_sid_args_list.append(';'.join(anonymous_sid_args))

            ps_args_dict[key] = ';\n'.join(anonymous_sid_args)

        elif key == "AUDIT_POLICY_SUBCATEGORY":
            audit_policy_args = []

            for idx, val in enumerate(checklist_values):

                # if val == 1:
                subcategory = str(subcategory_values[idx])

                arg = f"Write-Output '====';\nauditpol /get /subcategory:'{subcategory}' | select-string -pattern '{subcategory}'"

                audit_policy_args.append(arg)

            ps_args_dict[key] = ';\n'.join(audit_policy_args)

        elif key == "REG_CHECK":
            reg_check_args = []

            for idx, val in enumerate(checklist_values):

                # if val == 1:

                reg_key = reg_key_values[idx]
                reg_item = reg_item_values[idx]

                if reg_key.startswith("HKLM"):
                    reg_key = reg_key.replace("HKLM", "HKLM:")
                elif reg_key.startswith("HKU"):
                    reg_key = reg_key.replace("HKU", "HKU:")

                arg = f"Write-Output '====';\nGet-ItemPropertyValue -Path '{reg_key}' -Name '{reg_item}'"

                reg_check_args.append(arg)

            ps_args_dict[key] = ';\n'.join(reg_check_args)

        elif key == "WMI_POLICY":
            wmi_policy_args = []

            for idx, val in enumerate(checklist_values):

                # if val == 1:

                arg = "Write-Output '====';\n(Get-WmiObject -Class Win32_ComputerSystem).DomainRole"

                wmi_policy_args.append(arg)

            ps_args_dict[key] = ';\n'.join(wmi_policy_args)

        else:
            continue

    return ps_args_dict


def read_file(fname: str) -> dict:
    '''
    This function reads an Excel file containing audit data and returns a dictionary based on the audit type.

    The function takes a filename as an argument. The file should be an Excel file with each sheet containing 
    audit data for a different audit type. The function reads the data from each sheet and saves it in a 
    DataFrame. The DataFrames are stored in a dictionary where each key is the audit type and each value is 
    the corresponding DataFrame.

    :param fname: A string containing the filename of an Excel file.
    :return: A dictionary where each key is an audit type and each value is a DataFrame containing the 
             audit data for that type.
    '''

    data_dict = {
        "PASSWORD_POLICY": [],
        "REGISTRY_SETTING": [],
        "LOCKOUT_POLICY": [],
        "USER_RIGHTS_POLICY": [],
        "CHECK_ACCOUNT": [],
        "BANNER_CHECK": [],
        "ANONYMOUS_SID_SETTING": [],
        "AUDIT_POLICY_SUBCATEGORY": [],
        "REG_CHECK": [],
        "WMI_POLICY": []
    }

    xl = pd.ExcelFile(fname)
    # df = xl.parse(sheet_name=0)

    for type in data_dict:
        try:
            data_dict[type] = xl.parse(sheet_name=type)
        except ValueError as e:
            logging.error(f"{type} not found")
            logger.error('Value not found: %s', e)

    return data_dict


'''
This is the entry point of the script. It parses the command-line arguments for the path to the audit file, 
reads the audit file into a dictionary of DataFrames (one for each audit type), and generates the 
corresponding PowerShell commands for each audit type. 

The resulting PowerShell commands are then written to a .ps1 file for later execution. The name and location 
of the .ps1 file is determined by the name of the input audit file.

Usage: 
    python local_audit_command_generator.py --audit /path/to/audit/file

:param --audit: A string containing the path to the audit file.
:return: None
'''
if __name__ == '__main__':

    my_parser = argparse.ArgumentParser(
        description='A Customizable Multiprocessing Remote Security Audit Program')

    # Add the arguments
    my_parser.add_argument('--audit',
                           type=str,
                           required=True,
                           help='The path of audit file')

    # Execute parse_args()
    args = my_parser.parse_args()

    print('Aduit file:', args.audit)

    # fname = "src\Audit\CIS_MS_Windows_11_Enterprise_Level_1_v1.0.0.xlsx"
    fname = args.audit
    data_dict = read_file(fname)
    ps_args_dict = gen_ps_args(data_dict)

    # save file
    script_name = 'out\\script\\' + \
        fname.split("\\")[-1].replace("xlsx", "ps1")

    with open(script_name, 'w') as f:
        for key in ps_args_dict:
            for cmd in ps_args_dict[key]:
                f.write(cmd)
            f.write(";")
            # print(cmd)

    print("Done! File saved: %s", script_name)
