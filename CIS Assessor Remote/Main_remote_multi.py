import pandas as pd
import platform
import configparser
import time
from pypsexec.client import Client
from multiprocessing import Pool, Manager

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
}'''

# actual_value_dict = {}

# ps_args_dict = {}


def checkOS():
    info = platform.uname()
    os_version = info.system + info.release
    print(f"Operating System Version: {os_version}")

    if os_version != "Windows10":
        print("Incorrect OS")
        exit()


def compare_audit_result(actual_value, expected_value):

    result_dict = {"Success and Failure": "Success, Failure",
                   "Success": "Success",
                   "Failure": "Failure",
                   "No Auditing": "Not Configured"}

    if "||" in expected_value:
        expected_list = expected_value.split("||")
        for i in expected_list:
            i = i.strip()
            if result_dict[actual_value] == i:
                return True

    elif result_dict[actual_value] == expected_value:

        return True

    return False


def gen_ps_args(data_dict):
    ps_args_dict = {}

    for key, df in data_dict.items():

        checklist_values = df['Checklist'].values
        description_values = df['Description'].values
        reg_key_values = df['Reg Key'].values
        reg_item_values = df['Reg Item'].values
        subcategory_values = df['Audit Policy Subcategory'].values
        right_type_values = df['Right type'].values

        actual_value_list = []

        if key == "REGISTRY_SETTING":

            reg_value_args = []
            reg_value_args_list = []

            for idx, val in enumerate(checklist_values):
                if val == 1:
                    # generate command list for getting regristry value
                    reg_key = str(reg_key_values[idx])
                    reg_item = str(reg_item_values[idx])

                    if reg_key.startswith("HKLM"):
                        reg_key = reg_key.replace("HKLM", "HKLM:")
                    elif reg_key.startswith("HKU"):
                        reg_key = reg_key.replace("HKU", "HKU:")

                    arg = f"Write-Output '====';Get-ItemPropertyValue -Path '{reg_key}' -Name '{reg_item}'"
                    reg_value_args.append(arg)

                    if len(reg_value_args) == 50:
                        # print(reg_value_args)
                        reg_value_args_list.append(
                            ';'.join(reg_value_args))
                        reg_value_args = []

            reg_value_args_list.append(';'.join(reg_value_args))

            ps_args_dict[key] = reg_value_args_list

            continue

        elif key == "PASSWORD_POLICY":

            pwd_policy_args = []
            pwd_policy_args_list = []

            for idx, val in enumerate(checklist_values):
                if val == 1:

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
                        # result_lists.append("Manual")

                    elif "Force logoff when logon hours expire" in description:
                        subcategory = 'ForceLogoffWhenHourExpire ='

                    else:
                        actual_value_list.append("")

                    arg = f"Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern '{subcategory}'"

                    pwd_policy_args.append(arg)

                    if len(pwd_policy_args) == 50:
                        # print(pwd_policy_args)
                        pwd_policy_args_list.append(
                            ';'.join(pwd_policy_args))
                        pwd_policy_args = []

            pwd_policy_args_list.append(';'.join(pwd_policy_args))

            ps_args_dict[key] = pwd_policy_args_list

            continue

        elif key == "LOCKOUT_POLICY":

            lockout_policy_args = []
            for idx, val in enumerate(checklist_values):
                if val == 1:

                    # generate command list for getting lockout policy value
                    description = str(description_values[idx])

                    if "Account lockout duration" in description:
                        lockout_policy_args.append(
                            "net accounts | select-string -pattern 'Lockout duration'")

                    elif "Account lockout threshold" in description:
                        lockout_policy_args.append(
                            "net accounts | select-string -pattern 'Lockout threshold'")

                    elif "Reset account lockout counter" in description:
                        lockout_policy_args.append(
                            "net accounts | select-string -pattern 'Lockout observation window'")
                    else:
                        lockout_policy_args.append("")

            ps_args_dict[key] = lockout_policy_args

        elif key == "USER_RIGHTS_POLICY":

            user_rights_args = []
            user_rights_args_list = []

            for idx, val in enumerate(checklist_values):

                if val == 1:
                    right_type = str(right_type_values[idx])

                    arg = f"Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern '{right_type}'"

                    user_rights_args.append(arg)

                    if len(user_rights_args) == 50:
                        user_rights_args_list.append(
                            ';'.join(user_rights_args))
                        user_rights_args = []

            user_rights_args_list.append(';'.join(user_rights_args))

            ps_args_dict[key] = user_rights_args_list

        elif key == "CHECK_ACCOUNT":
            check_account_args = []
            for idx, val in enumerate(checklist_values):
                if val == 1:

                    # generate command list for getting check account value
                    description = str(description_values[idx])

                    if "Guest account status" in description:
                        check_account_args.append(
                            "net user guest | select-string -pattern 'Account active'")

                    elif "Rename administrator account" in description:
                        check_account_args.append(
                            "net user administrator | select-string -pattern 'User name'")

                    elif "Rename guest account" in description:
                        check_account_args.append(
                            "net user guest | select-string -pattern 'User name'")
                    else:
                        check_account_args.append("")

            ps_args_dict[key] = check_account_args

        elif key == "BANNER_CHECK":
            banner_check_args = []
            banner_check_args_list = []

            for idx, val in enumerate(checklist_values):
                if val == 1:
                    # generate command list for getting regristry value
                    reg_key = str(reg_key_values[idx])
                    reg_item = str(reg_item_values[idx])

                    if reg_key.startswith("HKLM"):
                        reg_key = reg_key.replace("HKLM", "HKLM:")
                    elif reg_key.startswith("HKU"):
                        reg_key = reg_key.replace("HKU", "HKU:")

                    arg = f"Write-Output '====';Get-ItemPropertyValue -Path '{reg_key}' -Name '{reg_item}'"
                    banner_check_args.append(arg)

                    if len(banner_check_args) == 50:
                        # print(banner_check_args)
                        banner_check_args_list.append(
                            ';'.join(banner_check_args))
                        banner_check_args = []

            banner_check_args_list.append(';'.join(banner_check_args))

            ps_args_dict[key] = banner_check_args_list

        elif key == "ANONYMOUS_SID_SETTING":

            anonymous_sid_args = []
            anonymous_sid_args_list = []

            for idx, val in enumerate(checklist_values):
                if val == 1:

                    # generate command list for getting password policy value
                    description = str(description_values[idx])

                    if "Allow anonymous SID/Name translation" in description:
                        subcategory = 'LSAAnonymousNameLookup ='
                    else:
                        actual_value_list.append("")

                    arg = f"Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern '{subcategory}'"

                    anonymous_sid_args.append(arg)

                    if len(anonymous_sid_args) == 50:
                        # print(anonymous_sid_args)
                        anonymous_sid_args_list.append(
                            ';'.join(anonymous_sid_args))
                        anonymous_sid_args = []

            anonymous_sid_args_list.append(';'.join(anonymous_sid_args))

            ps_args_dict[key] = anonymous_sid_args_list

            continue

        elif key == "AUDIT_POLICY_SUBCATEGORY":
            audit_policy_args = []
            audit_policy_args_list = []

            for idx, val in enumerate(checklist_values):

                if val == 1:
                    subcategory = str(subcategory_values[idx])

                    arg = f"Write-Output '===='; auditpol /get /subcategory:'{subcategory}' | select-string -pattern '{subcategory}'"

                    audit_policy_args.append(arg)

                    if len(audit_policy_args) == 50:
                        audit_policy_args_list.append(
                            ';'.join(audit_policy_args))
                        audit_policy_args = []

            audit_policy_args_list.append(';'.join(audit_policy_args))

            ps_args_dict[key] = audit_policy_args_list

        elif key == "REG_CHECK":
            reg_check_args = []
            reg_check_args_list = []

            for idx, val in enumerate(checklist_values):

                if val == 1:

                    reg_key = reg_key_values[idx]
                    reg_item = reg_item_values[idx]

                    if reg_key.startswith("HKLM"):
                        reg_key = reg_key.replace("HKLM", "HKLM:")
                    elif reg_key.startswith("HKU"):
                        reg_key = reg_key.replace("HKU", "HKU:")

                    arg = f"Write-Output '====';Get-ItemPropertyValue -Path '{reg_key}' -Name '{reg_item}'"

                    reg_check_args.append(arg)

            reg_check_args_list.append(';'.join(reg_check_args))

            ps_args_dict[key] = reg_check_args_list

        else:
            continue

    return ps_args_dict


def compare_reg_value(ip_addr, actual_value_list, data_dict):

    # registry value
    df = data_dict["REGISTRY_SETTING"]
    checklist_values = df['Checklist'].values
    idx_values = df['Index'].values
    value_data_values = df['Value Data'].values

    # actual_value_list = actual_value_dict["REGISTRY_SETTING"]
    result_lists = []

    for idx, val in enumerate(checklist_values):

        pass_result = True

        if val == 1:

            expected_value = str(value_data_values[idx]).lower()

            if actual_value_list[idx] == "":
                actual_value_list[idx] = "Null"

            actual_value = actual_value_list[idx].lower()

            if actual_value != "null" and idx_values[idx] == "2.3.10.7" or idx_values[idx] == "2.3.10.8":
                expected_value = expected_value.lower().split(" && ")[
                    0].strip()
                actual_value = [s.lower() for s in actual_value]

                actual_value = ''.join(actual_value)

                if expected_value == actual_value:
                    pass_result = True
                else:
                    pass_result = False

            elif actual_value != "null" and "||" in expected_value:
                expected_value = expected_value.split(" || ")
                if str(actual_value) in expected_value:
                    pass_result = True
                else:
                    pass_result = False

            elif actual_value != "null" and "[" in expected_value:
                vals = expected_value.strip("[]").split("..")
                min_val = vals[0]
                max_val = vals[1]

                if min_val == "min":
                    if int(actual_value) <= int(max_val):
                        pass_result = True
                elif max_val == "max":
                    if int(actual_value) >= int(min_val):
                        pass_result = False
                else:
                    if int(actual_value) >= int(min_val) and int(actual_value) <= int(max_val):
                        pass_result = True

            else:
                if str(expected_value) == str(actual_value):
                    pass_result = True
                else:
                    pass_result = False

            if pass_result:
                print(
                    f"{ip_addr} | {idx_values[idx]}: Pass | Expected: {expected_value} | Actual: {actual_value}")
                result_lists.append("Pass")
            else:
                print(
                    f"{ip_addr} | {idx_values[idx]}: Fail | Expected: {expected_value} | Actual: {actual_value}")
                result_lists.append("Fail")

        else:
            actual_value_list.append("")
            result_lists.append("")

    col_name1 = ip_addr + ' | Actual Value'
    col_name2 = ip_addr + ' | Result'

    df[col_name1] = actual_value_list
    df[col_name2] = result_lists

    # data_dict["REGISTRY_SETTING"] = df

    return df


def get_registry_actual_value(args_list, ip):

    try:
        win_client = Client(
            ip[0], username=ip[1], password=ip[2])
        win_client.connect()
        win_client.create_service()

        actual_values = ''
        for arg in args_list:
            stdout, stderr, rc = win_client.run_executable(
                "powershell.exe", arguments=arg)

            output = stdout.decode("utf-8").replace('\r\n', '')
            actual_values = actual_values + output

        print("arg:", actual_values)

    finally:
        win_client.remove_service()
        win_client.disconnect()
        # return actual_values

    actual_value_list = actual_values.split("====")
    actual_value_list.pop(0)

    print(actual_value_list)

    # print("length of value", len(actual_value_list))
    # actual_value_dict["REGISTRY_SETTING"] = actual_value_list
    return actual_value_list


def compare_pwd_policy(ip_addr, actual_value_list, data_dict):
    # password policy
    df = data_dict["PASSWORD_POLICY"]
    checklist_values = df['Checklist'].values
    description_values = df['Description'].values
    idx_values = df['Index'].values
    value_data_values = df['Value Data'].values

    # actual_value_list = actual_value_dict["PASSWORD_POLICY"]
    result_lists = []

    for idx, val in enumerate(checklist_values):

        pass_result = True

        if val == 1:

            description = description_values[idx]
            expected_value = str(value_data_values[idx]).lower()

            actual_value = actual_value_list[idx].split("=")[-1].strip()
            actual_value_list[idx] = actual_value

            if "Enforce password history" in description:
                try:
                    actual_value = int(actual_value)
                    if actual_value >= int(expected_value):
                        pass_result = True
                    else:
                        pass_result = False
                except ValueError:
                    print(f"Invalid value: {actual_value}")
                    pass_result = False

            elif "Maximum password age" in description:
                try:
                    actual_value = int(actual_value)

                    if actual_value > 0 and actual_value <= int(expected_value):
                        pass_result = True

                    else:
                        pass_result = False
                except ValueError:
                    print(f"Invalid value: {actual_value}")
                    pass_result = False

            elif "Minimum password age" in description:
                try:
                    actual_value = int(actual_value)
                    if actual_value >= int(expected_value):
                        pass_result = True
                    else:
                        pass_result = False
                except ValueError:
                    print(f"Invalid value: {actual_value}")
                    pass_result = False

            elif "Minimum password length" in description:
                try:
                    actual_value = int(actual_value)
                    if actual_value >= int(expected_value):
                        pass_result = True
                    else:
                        pass_result = False
                except ValueError:
                    print(f"Invalid value: {actual_value}")
                    pass_result = False

            elif "complexity requirements" in description:
                try:
                    actual_value = int(actual_value)
                    if actual_value == int(expected_value):
                        pass_result = True
                    else:
                        pass_result = False
                except ValueError:
                    print(f"Invalid value: {actual_value}")
                    pass_result = False

            elif "reversible encryption" in description:
                try:
                    actual_value = int(actual_value)
                    if actual_value == int(expected_value):
                        pass_result = True
                    else:
                        pass_result = False
                except ValueError:
                    print(f"Invalid value: {actual_value}")
                    pass_result = False

            elif "Administrator account lockout" in description:
                result_lists.append("Manual")
                continue

            elif "Force logoff when logon hours expire" in description:
                try:
                    actual_value = int(actual_value)
                    if actual_value == int(expected_value):
                        pass_result = True
                    else:
                        pass_result = False
                except ValueError:
                    print(f"Invalid value: {actual_value}")
                    pass_result = False

            else:
                pass_result = False

            if pass_result:
                print(
                    f"{ip_addr} | {idx_values[idx]}: Pass | Expected: {expected_value} | Actual: {actual_value}")
                result_lists.append("Pass")
            else:
                print(
                    f"{ip_addr} | {idx_values[idx]}: Fail | Expected: {expected_value} | Actual: {actual_value}")
                result_lists.append("Fail")

        else:
            actual_value_list.append("")
            result_lists.append("")

    col_name1 = ip_addr + ' | Actual Value'
    col_name2 = ip_addr + ' | Result'

    df[col_name1] = actual_value_list
    df[col_name2] = result_lists

    # data_dict["PASSWORD_POLICY"] = df
    return df


def get_pwd_policy_actual_value(args_list, ip):
    try:

        win_client = Client(
            ip[0], username=ip[1], password=ip[2])
        win_client.connect()
        win_client.create_service()

        # dump all pwd policies
        arg = r"if (!(Test-Path -Path C:\temp )) { New-Item -ItemType directory -Path C:\temp };secedit /export /cfg C:\temp\secpol.cfg /areas SECURITYPOLICY"
        win_client.run_executable(
            "powershell.exe", arguments=arg)

        # get pwd policy value
        actual_values = ''
        for arg in args_list:

            stdout, stderr, rc = win_client.run_executable(
                "powershell.exe", arguments=arg)

            output = stdout.decode("utf-8").replace('\r\n', '')
            actual_values = actual_values + output
    finally:
        win_client.remove_service()
        win_client.disconnect()

    actual_value_list = actual_values.split("====")
    actual_value_list.pop(0)
    # print(actual_value_list)
    # print("length of value", len(actual_value_list))
    # actual_value_dict["PASSWORD_POLICY"] = actual_value_list
    return actual_value_list


def get_user_rights_actual_value(args_list, ip):
    try:

        win_client = Client(
            ip[0], username=ip[1], password=ip[2])
        win_client.connect()
        win_client.create_service()

        # dump all user rights
        arg = r"if (!(Test-Path -Path C:\temp )) { New-Item -ItemType directory -Path C:\temp };secedit /export /cfg C:\temp\secpol.cfg /areas user_rights"
        win_client.run_executable(
            "powershell.exe", arguments=arg)

        # get user rights value
        actual_values = ''
        # print(len(args_list))
        for arg in args_list:

            stdout, stderr, rc = win_client.run_executable(
                "powershell.exe", arguments=arg)

            output = stdout.decode("utf-8").replace('\r\n', '')
            actual_values = actual_values + output

    finally:
        win_client.remove_service()
        win_client.disconnect()

    actual_value_list = actual_values.split("====")
    actual_value_list.pop(0)

    for i in range(len(actual_value_list)):
        actual_value_list[i] = actual_value_list[i].split("=")[-1].strip()

    # print(actual_value_list)
    # print("length of value", len(actual_value_list))
    # actual_value_dict["USER_RIGHTS_POLICY"] = actual_value_list
    return actual_value_list


def compare_user_right_result(right_type, expected_value, actual_value):
    user_right_dict = {"": "",
                       "Administrators": "*S-1-5-32-544",
                       "Users": "*S-1-5-32-545",
                       "Guests": "*S-1-5-32-546",
                       "Remote Desktop Users": "*S-1-5-32-555",
                       "LOCAL SERVICE": "*S-1-5-19",
                       "NETWORK SERVICE": "*S-1-5-20",
                       "SERVICE": "*S-1-5-6",
                       "Virtual Machines": "*S-1-5-83-0",
                       "Local account": "*S-1-5-113",
                       "Window Manager\Window Manager Group": "*S-1-5-90-0",
                       "NT SERVICE\WdiServiceHost": "*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"}

    actual_set = set(actual_value.split(','))
    sid_set = set()
    sid_set_list = []

    if '(' in expected_value or ')' in expected_value:

        if right_type == 'SeIncreaseBasePriorityPrivilege':
            sid_set_list.append(set([user_right_dict['Administrators'],
                                user_right_dict["Window Manager\Window Manager Group"]]))
        elif right_type == 'SeCreateSymbolicLinkPrivilege':
            sid_set_list.append(set([user_right_dict['Administrators']]))
            sid_set_list.append(
                set([user_right_dict['Administrators'], user_right_dict["Virtual Machines"]]))
        elif right_type == 'SeSystemProfilePrivilege':
            sid_set_list.append(set(
                [user_right_dict['Administrators'], user_right_dict["NT SERVICE\WdiServiceHost"]]))

    else:
        if '&' in expected_value:
            user_list = expected_value.split(" && ")
            for u in user_list:
                sid_set.add(user_right_dict[u])

        elif '|' in expected_value:
            user_list = expected_value.split(" || ")
            for u in user_list:
                sid_set.add(user_right_dict[u])
        else:
            sid_set.add(user_right_dict[expected_value])

        sid_set_list.append(sid_set)

    # print(actual_set)
    # print(sid_set_list)
    if actual_set in sid_set_list:
        return True
    else:
        return False


def compare_user_rights(ip_addr, actual_value_list, data_dict):
    # user rights
    df = data_dict["USER_RIGHTS_POLICY"]
    checklist_values = df['Checklist'].values
    idx_values = df['Index'].values
    value_data_values = df['Value Data'].values
    right_type_values = df['Right type'].values

    # actual_value_list = actual_value_dict["USER_RIGHTS_POLICY"]
    result_lists = []

    for idx, val in enumerate(checklist_values):

        pass_result = True

        if val == 1:

            right_type = str(right_type_values[idx])
            expected_value = str(value_data_values[idx])
            actual_value = actual_value_list[idx]

            try:
                result = compare_user_right_result(
                    right_type, expected_value, actual_value)
                if result:
                    pass_result = True
                else:
                    pass_result = False

            except (configparser.NoOptionError, KeyError):
                null_value_list = ['SeTrustedCredManAccessPrivilege',
                                   'SeTcbPrivilege',
                                   'SeCreateTokenPrivilege',
                                   'SeCreatePermanentPrivilege',
                                   'SeEnableDelegationPrivilege',
                                   'SeLockMemoryPrivilege',
                                   'SeReLabelPrivilege'
                                   ]
                if right_type in null_value_list:
                    pass_result = True
                else:
                    actual_value = "Invalid key"
                    pass_result = False

            if pass_result:
                print(
                    f"{ip_addr} | {idx_values[idx]}: Pass | Expected: {expected_value} | Actual: {actual_value}")
                result_lists.append("Pass")
            else:
                print(
                    f"{ip_addr} | {idx_values[idx]}: Fail | Expected: {expected_value} | Actual: {actual_value}")
                result_lists.append("Fail")

        else:
            actual_value_list.append("")
            result_lists.append("")

    col_name1 = ip_addr + ' | Actual Value'
    col_name2 = ip_addr + ' | Result'

    df[col_name1] = actual_value_list
    df[col_name2] = result_lists

    # data_dict["USER_RIGHTS_POLICY"] = df
    return df


def get_lockout_policy_actual_value(args_list, ip):
    actual_value_list = []
    try:

        win_client = Client(
            ip[0], username=ip[1], password=ip[2])
        win_client.connect()
        win_client.create_service()

        for arg in args_list:
            stdout, stderr, rc = win_client.run_executable(
                "powershell.exe", arguments=arg)

            output = stdout.decode("utf-8").replace('\r\n', '')
            actual_value_list.append(output.split()[-1].strip())

    finally:
        win_client.remove_service()
        win_client.disconnect()

    # print(actual_value_list)
    # print("length of value", len(actual_value_list))
    # actual_value_dict["LOCKOUT_POLICY"] = actual_value_list
    return actual_value_list


def compare_lockout_policy(ip_addr, actual_value_list, data_dict):
    # password policy
    df = data_dict["LOCKOUT_POLICY"]
    checklist_values = df['Checklist'].values
    description_values = df['Description'].values
    idx_values = df['Index'].values
    value_data_values = df['Value Data'].values

    # actual_value_list = actual_value_dict["LOCKOUT_POLICY"]
    result_lists = []

    for idx, val in enumerate(checklist_values):

        pass_result = True

        if val == 1:

            description = description_values[idx]
            expected_value = str(value_data_values[idx]).lower()
            actual_value = actual_value_list[idx]

            if "Account lockout duration" in description:
                try:
                    actual_value = int(actual_value)
                    if actual_value >= int(expected_value):
                        pass_result = True
                    else:
                        pass_result = False
                except ValueError:
                    pass_result = False
            elif "Account lockout threshold" in description:
                if actual_value == "Never":
                    pass_result = False
                else:
                    try:
                        actual_value = int(actual_value)

                        if actual_value > 0 and actual_value <= int(expected_value):
                            pass_result = True
                        else:
                            pass_result = False
                    except ValueError:
                        pass_result = False
            elif "Reset account lockout counter" in description:
                try:
                    actual_value = int(actual_value)

                    if actual_value >= int(expected_value):
                        pass_result = True
                    else:
                        pass_result = False
                except ValueError:
                    pass_result = False
            else:
                pass_result = False

            if pass_result:
                print(
                    f"{ip_addr} | {idx_values[idx]}: Pass | Expected: {expected_value} | Actual: {actual_value}")
                result_lists.append("Pass")
            else:
                print(
                    f"{ip_addr} | {idx_values[idx]}: Fail | Expected: {expected_value} | Actual: {actual_value}")
                result_lists.append("Fail")

        else:
            actual_value_list.append("")
            result_lists.append("")

    col_name1 = ip_addr + ' | Actual Value'
    col_name2 = ip_addr + ' | Result'

    df[col_name1] = actual_value_list
    df[col_name2] = result_lists

    # data_dict["LOCKOUT_POLICY"] = df
    return df


def get_check_account_actual_value(args_list, ip):
    actual_value_list = []

    try:

        win_client = Client(
            ip[0], username=ip[1], password=ip[2])
        win_client.connect()
        win_client.create_service()

        # get check account value
        for arg in args_list:

            stdout, stderr, rc = win_client.run_executable(
                "powershell.exe", arguments=arg)

            output = stdout.decode("utf-8").replace('\r\n', '')
            actual_value_list.append(output.split()[-1].strip())

    finally:
        win_client.remove_service()
        win_client.disconnect()

    # print(actual_value_list)
    # print("length of value", len(actual_value_list))
    # actual_value_dict["CHECK_ACCOUNT"] = actual_value_list
    return actual_value_list


def compare_check_account(ip_addr, actual_value_list, data_dict):

    # user rights
    df = data_dict["CHECK_ACCOUNT"]
    checklist_values = df['Checklist'].values
    idx_values = df['Index'].values
    value_data_values = df['Value Data'].values
    description_values = df['Description'].values

    # actual_value_list = actual_value_dict["CHECK_ACCOUNT"]
    result_lists = []

    for idx, val in enumerate(checklist_values):

        pass_result = True

        if val == 1:

            description = str(description_values[idx])
            expected_value = str(value_data_values[idx]).lower()
            actual_value = actual_value_list[idx].lower()

            if ("Rename administrator account" in description or "Rename guest account" in description) and expected_value == actual_value:
                pass_result = False
            elif expected_value != actual_value:
                pass_result = False
            else:
                pass_result = True

            if pass_result:
                print(
                    f"{ip_addr} | {idx_values[idx]}: Pass | Expected: {expected_value} | Actual: {actual_value}")
                result_lists.append("Pass")
            else:
                print(
                    f"{ip_addr} | {idx_values[idx]}: Fail | Expected: {expected_value} | Actual: {actual_value}")
                result_lists.append("Fail")

        else:
            actual_value_list.append("")
            result_lists.append("")

    col_name1 = ip_addr + ' | Actual Value'
    col_name2 = ip_addr + ' | Result'

    df[col_name1] = actual_value_list
    df[col_name2] = result_lists

    # data_dict["CHECK_ACCOUNT"] = df
    return df


def get_check_banner_actual_value(args_list, ip):
    try:

        win_client = Client(
            ip[0], username=ip[1], password=ip[2])
        win_client.connect()
        win_client.create_service()

        actual_values = ''
        for arg in args_list:
            stdout, stderr, rc = win_client.run_executable(
                "powershell.exe", arguments=arg)

            output = stdout.decode(
                "utf-8").replace('\r\n', '').replace("\x00", "")
            actual_values = actual_values + output

    finally:
        win_client.remove_service()
        win_client.disconnect()
        # return actual_values

    actual_value_list = actual_values.split("====")
    actual_value_list.pop(0)
    # print(actual_value_list)
    # print("length of value", len(actual_value_list))
    # actual_value_dict["BANNER_CHECK"] = actual_value_list
    return actual_value_list


def compare_banner_check(ip_addr, actual_value_list, data_dict):
    # banner check
    df = data_dict["BANNER_CHECK"]
    checklist_values = df['Checklist'].values
    idx_values = df['Index'].values
    value_data_values = df['Value Data'].values

    # actual_value_list = actual_value_dict["BANNER_CHECK"]
    result_lists = []

    for idx, val in enumerate(checklist_values):

        pass_result = True

        if val == 1:

            expected_value = str(value_data_values[idx]).lower()
            actual_value = actual_value_list[idx]

            if actual_value == "":
                pass_result = False
            else:
                pass_result = True

            if pass_result:
                print(
                    f"{ip_addr} | {idx_values[idx]}: Pass | Expected: {expected_value} | Actual: {actual_value}")
                result_lists.append("Pass")
            else:
                print(
                    f"{ip_addr} | {idx_values[idx]}: Fail | Expected: {expected_value} | Actual: {actual_value}")
                result_lists.append("Fail")

        else:
            actual_value_list.append("")
            result_lists.append("")

    col_name1 = ip_addr + ' | Actual Value'
    col_name2 = ip_addr + ' | Result'

    df[col_name1] = actual_value_list
    df[col_name2] = result_lists

    # data_dict["BANNER_CHECK"] = df
    return df


def get_anonymous_sid_value(args_list, ip):
    try:

        win_client = Client(
            ip[0], username=ip[1], password=ip[2])
        win_client.connect()
        win_client.create_service()

        # dump all pwd policies
        arg = r"if (!(Test-Path -Path C:\temp )) { New-Item -ItemType directory -Path C:\temp };secedit /export /cfg C:\temp\secpol.cfg /areas SECURITYPOLICY"
        win_client.run_executable(
            "powershell.exe", arguments=arg)

        # get pwd policy value
        actual_values = ''
        for arg in args_list:
            stdout, stderr, rc = win_client.run_executable(
                "powershell.exe", arguments=arg)
            output = stdout.decode("utf-8").replace('\r\n', '')
            actual_values = actual_values + output
    finally:
        win_client.remove_service()
        win_client.disconnect()

    actual_value_list = actual_values.split("====")
    actual_value_list.pop(0)
    # print(actual_value_list)
    # print("length of value", len(actual_value_list))
    # actual_value_dict["ANONYMOUS_SID_SETTING"] = actual_value_list
    return actual_value_list


def compare_anonymous_sid(ip_addr, actual_value_list, data_dict):
    # anonymous sid setting
    df = data_dict["ANONYMOUS_SID_SETTING"]
    checklist_values = df['Checklist'].values
    description_values = df['Description'].values
    idx_values = df['Index'].values
    value_data_values = df['Value Data'].values

    # actual_value_list = actual_value_dict["ANONYMOUS_SID_SETTING"]
    result_lists = []

    for idx, val in enumerate(checklist_values):

        pass_result = True

        if val == 1:

            description = description_values[idx]
            expected_value = str(value_data_values[idx]).lower()

            actual_value = actual_value_list[idx].split("=")[-1].strip()
            actual_value_list[idx] = actual_value

            if "Allow anonymous SID/Name translation" in description:
                try:
                    actual_value = int(actual_value)
                    if actual_value == int(expected_value):
                        pass_result = True
                    else:
                        pass_result = False
                except ValueError:
                    print(f"Invalid value: {actual_value}")
                    pass_result = False

            if pass_result:
                print(
                    f"{ip_addr} | {idx_values[idx]}: Pass | Expected: {expected_value} | Actual: {actual_value}")
                result_lists.append("Pass")
            else:
                print(
                    f"{ip_addr} | {idx_values[idx]}: Fail | Expected: {expected_value} | Actual: {actual_value}")
                result_lists.append("Fail")

        else:
            actual_value_list.append("")
            result_lists.append("")

    col_name1 = ip_addr + ' | Actual Value'
    col_name2 = ip_addr + ' | Result'

    df[col_name1] = actual_value_list
    df[col_name2] = result_lists

    # data_dict["ANONYMOUS_SID_SETTING"] = df
    return df


def get_audit_policy_actual_value(args_list, ip):

    try:

        win_client = Client(
            ip[0], username=ip[1], password=ip[2])
        win_client.connect()
        win_client.create_service()

        # get audit policy value
        actual_values = ''
        for arg in args_list:

            stdout, stderr, rc = win_client.run_executable(
                "powershell.exe", arguments=arg)

            output = stdout.decode("utf-8").replace('\r\n', '')
            actual_values = actual_values + output
    finally:
        win_client.remove_service()
        win_client.disconnect()

    actual_value_list = actual_values.split("====")
    actual_value_list.pop(0)

    for i in range(len(actual_value_list)):
        val = actual_value_list[i].split()[-1].strip()
        if val == "Auditing":
            actual_value_list[i] = "No Auditing"
        else:
            actual_value_list[i] = val

    # print(actual_value_list)
    # print("length of value", len(actual_value_list))
    # actual_value_dict["AUDIT_POLICY_SUBCATEGORY"] = actual_value_list
    return actual_value_list


def compare_audit_policy(ip_addr, actual_value_list, data_dict):

    # audit policy
    df = data_dict["AUDIT_POLICY_SUBCATEGORY"]
    checklist_values = df['Checklist'].values
    idx_values = df['Index'].values
    value_data_values = df['Value Data'].values

    # actual_value_list = actual_value_dict["AUDIT_POLICY_SUBCATEGORY"]
    result_lists = []

    for idx, val in enumerate(checklist_values):

        pass_result = True

        if val == 1:

            expected_value = str(value_data_values[idx]).lower()
            actual_value = actual_value_list[idx]

            pass_result = compare_audit_result(actual_value, expected_value)

            if pass_result:
                print(
                    f"{ip_addr} | {idx_values[idx]}: Pass | Expected: {expected_value} | Actual: {actual_value}")
                result_lists.append("Pass")
            else:
                print(
                    f"{ip_addr} | {idx_values[idx]}: Fail | Expected: {expected_value} | Actual: {actual_value}")
                result_lists.append("Fail")

        else:
            actual_value_list.append("")
            result_lists.append("")

    col_name1 = ip_addr + ' | Actual Value'
    col_name2 = ip_addr + ' | Result'

    df[col_name1] = actual_value_list
    df[col_name2] = result_lists

    # data_dict["AUDIT_POLICY_SUBCATEGORY"] = df
    return df


def get_reg_check_actual_value(args_list, ip):
    try:

        win_client = Client(
            ip[0], username=ip[1], password=ip[2])
        win_client.connect()
        win_client.create_service()

        actual_values = ''
        for arg in args_list:
            stdout, stderr, rc = win_client.run_executable(
                "powershell.exe", arguments=arg)

            output = stdout.decode("utf-8").replace('\r\n', '')
            actual_values = actual_values + output

    finally:
        win_client.remove_service()
        win_client.disconnect()
        # return actual_values

    actual_value_list = actual_values.split("====")
    actual_value_list.pop(0)
    # print(actual_value_list)
    # print("length of value", len(actual_value_list))
    # actual_value_dict["REG_CHECK"] = actual_value_list
    return actual_value_list


def compare_reg_check(ip_addr, actual_value_list, data_dict):
    # reg check
    df = data_dict["REG_CHECK"]
    checklist_values = df['Checklist'].values
    idx_values = df['Index'].values
    value_data_values = df['Value Data'].values

    # actual_value_list = actual_value_dict["REG_CHECK"]
    result_lists = []

    for idx, val in enumerate(checklist_values):

        pass_result = True

        if val == 1:

            expected_value = str(value_data_values[idx]).lower()

            if actual_value_list[idx] == "":
                actual_value_list[idx] = "Null"

            actual_value = actual_value_list[idx].lower()

            if actual_value == 'null' or actual_value == 'disabled':
                pass_result = True
            else:
                pass_result = False

            if pass_result:
                print(
                    f"{ip_addr} | {idx_values[idx]}: Pass | Expected: {expected_value} | Actual: {actual_value}")
                result_lists.append("Pass")
            else:
                print(
                    f"{ip_addr} | {idx_values[idx]}: Fail | Expected: {expected_value} | Actual: {actual_value}")
                result_lists.append("Fail")

        else:
            actual_value_list.append("")
            result_lists.append("")

    col_name1 = ip_addr + ' | Actual Value'
    col_name2 = ip_addr + ' | Result'

    df[col_name1] = actual_value_list
    df[col_name2] = result_lists

    # data_dict["REG_CHECK"] = df
    return df


def get_actual_values(ip, ps_args_dict, data_dict):

    new_dict = {}

    for key, args_list in ps_args_dict.items():

        if key == "PASSWORD_POLICY":
            print(f"{ip[0]} | Getting {key} value......")
            if args_list == [''] or args_list == []:
                actual_value_list = []
            else:
                actual_value_list = get_pwd_policy_actual_value(args_list, ip)

            print(f"{ip[0]} | Comparing {key} value......")
            new_df = compare_pwd_policy(ip[0], actual_value_list, data_dict)
        elif key == "REGISTRY_SETTING":
            print(f"{ip[0]} | Getting {key} value......")
            # continue
            if args_list == [''] or args_list == []:
                actual_value_list = []
            else:
                actual_value_list = get_registry_actual_value(args_list, ip)
            print(f"{ip[0]} | Comparing {key} value......")
            new_df = compare_reg_value(ip[0], actual_value_list, data_dict)
        elif key == "LOCKOUT_POLICY":
            print(f"{ip[0]} | Getting {key} value......")
            # continue
            if args_list == [''] or args_list == []:
                actual_value_list = []
            else:
                actual_value_list = get_lockout_policy_actual_value(
                    args_list, ip)
            print(f"{ip[0]} | Comparing {key} value......")
            new_df = compare_lockout_policy(
                ip[0], actual_value_list, data_dict)
        elif key == "USER_RIGHTS_POLICY":
            print(f"{ip[0]} | Getting {key} value......")
            # continue
            if args_list == [''] or args_list == []:
                actual_value_list = []
            else:
                actual_value_list = get_user_rights_actual_value(
                    args_list, ip)
            print(f"{ip[0]} | Comparing {key} value......")
            new_df = compare_user_rights(ip[0], actual_value_list, data_dict)
        elif key == "CHECK_ACCOUNT":
            print(f"{ip[0]} | Getting {key} value......")
            # continue
            if args_list == [''] or args_list == []:
                actual_value_list = []
            else:
                actual_value_list = get_check_account_actual_value(
                    args_list, ip)
            print(f"{ip[0]} | Comparing {key} value......")
            new_df = compare_check_account(ip[0], actual_value_list, data_dict)
        elif key == "BANNER_CHECK":
            print(f"{ip[0]} | Getting {key} value......")
            # continue
            actual_value_list = get_check_banner_actual_value(args_list, ip)
            print(f"{ip[0]} | Comparing {key} value......")
            new_df = compare_banner_check(ip[0], actual_value_list, data_dict)
        elif key == "ANONYMOUS_SID_SETTING":
            print(f"{ip[0]} | Getting {key} value......")
            # continue
            if args_list == [''] or args_list == []:
                actual_value_list = []
            else:
                actual_value_list = get_anonymous_sid_value(args_list, ip)
            print(f"{ip[0]} | Comparing {key} value......")
            new_df = compare_anonymous_sid(ip[0], actual_value_list, data_dict)
        elif key == "AUDIT_POLICY_SUBCATEGORY":
            print(f"{ip[0]} | Getting {key} value......")
            # continue
            if args_list == [''] or args_list == []:
                actual_value_list = []
            else:
                actual_value_list = get_audit_policy_actual_value(
                    args_list, ip)
            print(f"{ip[0]} | Comparing {key} value......")
            new_df = compare_audit_policy(ip[0], actual_value_list, data_dict)
        elif key == "REG_CHECK":
            print(f"{ip[0]} | Getting {key} value......")
            # continue
            if args_list == [''] or args_list == []:
                actual_value_list = []
            else:
                actual_value_list = get_reg_check_actual_value(args_list, ip)
            print(f"{ip[0]} | Comparing {key} value......")
            new_df = compare_reg_check(ip[0], actual_value_list, data_dict)

        new_dict[key] = new_df

    return new_dict


def read_file(fname):

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
    }

    xl = pd.ExcelFile(fname)
    # df = xl.parse(sheet_name=0)

    for type in data_dict:
        try:
            data_dict[type] = xl.parse(sheet_name=type)
        except ValueError:
            print(f"{type} not found")

    # print(data_dict)

    return data_dict


def save_file(out_fname, data_dict_list):

    all_frames = []

    for data_dict in data_dict_list:
        frames = []

        for df in data_dict.values():
            frames.append(df)
        result_rowwise = pd.concat(frames)
        all_frames.append(result_rowwise.reset_index(drop=True))

    result = pd.concat(all_frames, axis=1)

    result = result.loc[:, ~result.columns.duplicated()]
    # output a new CSV file
    result.to_csv(out_fname, index=False)
    print(f"Result saved into {out_fname}")


def configurations(config_fname):

    config_file = pd.ExcelFile(config_fname)

    configs = config_file.parse(sheet_name=0)

    ip_dict = {}
    ip_list = []

    ips = configs['IP Address'].values
    usernames = configs['Username'].values
    passwords = configs['Password'].values
    versions = configs['Windows Version'].values

    for idx, val in enumerate(ips):
        # ip_dict[val] = [usernames[idx], passwords[idx], versions[idx]]
        ip_list.append([ips[idx], usernames[idx],
                       passwords[idx], versions[idx]])

    # return ip_dict
    return ip_list


def run(ip, data_dict):
    print(f'IP: {ip[0]} scanning start....')
    start_t = time.time()

    ps_args_dict = gen_ps_args(data_dict)

    # get actual values and compare
    new_dict = get_actual_values(ip, ps_args_dict, data_dict)

    end_t = time.time()

    running_t = end_t - start_t
    print(f"IP: {ip[0]} | Running time: {running_t} seconds")
    return new_dict


if __name__ == '__main__':
    start_t0 = time.time()

    config_fname = 'src\config.xlsx'
    ip_list = configurations(config_fname)
    # print(ip_dict)

    # read input file
    src_fname = 'src\win10_v10.xlsx'
    # src_fname = 'src\win10_v10_test.xlsx'
    data_dict = read_file(src_fname)

    # generate powershell commands
    # ps_arg_list = gen_ps_args()
    # print("ps_cmd_list: ", ps_args_dict["USER_RIGHTS_POLICY"])

    # pool = Pool(processes=4)

    # result = pool.map(run, ip_list)

    with Manager() as manager:
        # initialize shared dictionary with data_dict
        shared_data_dict = manager.dict(data_dict)

        with Pool(processes=4) as pool:
            results = pool.starmap(
                run, [(ip, shared_data_dict) for ip in ip_list])

    # for ip in ip_list:
    #     run(ip, data_dict)

    # write output file
    out_fname = r"out\remote_output_v10.csv"
    save_file(out_fname, results)

    start_t = time.time()

    end_t0 = time.time()

    running_t0 = end_t0 - start_t0
    print(f"The script ran for {running_t0} seconds")
