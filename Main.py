import pandas as pd
import winreg
import platform
import subprocess
import configparser
import os


def checkOS():
    info = platform.uname()
    os_version = os_name = info.system + info.release
    print(f"Operating System Version: {os_version}")

    if os_version != "Windows10":
        print("Incorrect OS")
        exit()


def get_registry_value_HKLM(path, name):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
        value, regtype = winreg.QueryValueEx(key, name)
        winreg.CloseKey(key)
        return value
    except FileNotFoundError:
        print(f"Could not find the key or value in the registry.")
        return "Value Not found"
    except PermissionError:
        print(f"Access is denied")
        return "Access is denied"


def get_registry_value(path, name):
    try:
        if path.startswith("HKLM"):
            path = path.replace("HKLM\\", "")
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
        elif path.startswith("HKU"):
            path = path.replace("HKU\\", "")
            key = winreg.OpenKey(winreg.HKEY_USERS, path)
        else:
            return "Invalid path"

        value, regtype = winreg.QueryValueEx(key, name)
        winreg.CloseKey(key)
        return value
    except FileNotFoundError:
        print(f"Could not find the key or value in the registry.")
        return "Value Not found"
    except PermissionError:
        print(f"Access is denied")
        return "Access is denied"


def get_audit_policy(subcategory):
    try:
        cmd = f'auditpol /get /subcategory:"{subcategory}"'
        result = subprocess.run(
            cmd, shell=True, text=True, capture_output=True)
        output = result.stdout

        if output == "":
            return ""

        line = output.split('\n')[4]
        result = line.replace(subcategory, '').strip()
        return result

    except FileNotFoundError:
        print(f"Could not find the key or value in the group policy.")
        return "Value Not found"
    except PermissionError:
        print(f"Access is denied")
        return "Access is denied"


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
                return "Pass"

    elif result_dict[actual_value] == expected_value:

        return "Pass"

    return "Fail"


def get_pwd_policy(subcategory):

    try:
        subprocess.run(
            'secedit /export /cfg %temp%\\secpol.cfg /areas SECURITYPOLICY', shell=True, check=True)

        # Create a ConfigParser object
        config = configparser.ConfigParser()

        # Open the file in binary mode, read it, decode it and split it into lines
        with open(os.getenv('temp') + '\\secpol.cfg', 'rb') as f:
            content = f.read().decode('utf-16').split('\n')

        # Make ConfigParser read the lines
        config.read_string('\n'.join(content))

        # Get the value of PasswordComplexity
        result = config.get('System Access', subcategory)

        return result

    except FileNotFoundError:
        print(f"Could not find the key or value in the group policy.")
        return "Value Not found"
    except PermissionError:
        print(f"Access is denied")
        return "Access is denied"


def get_lockout_policy(policy_name):
    command = 'net accounts'
    output = subprocess.check_output(command, shell=True).decode()
    output_lines = output.split("\n")

    for line in output_lines:
        if policy_name in line:

            return line.strip().split()[-1]


def get_guest_account(policy_name):
    command = 'net user guest'
    output = subprocess.check_output(command, shell=True).decode()
    output_lines = output.split("\n")

    for line in output_lines:
        if policy_name in line:

            return line.strip().split()[-1]


def get_admin_account(policy_name):
    command = 'net user administrator'
    output = subprocess.check_output(command, shell=True).decode()
    output_lines = output.split("\n")

    for line in output_lines:
        if policy_name in line:

            return line.strip().split()[-1]


def check_result(src_df):
    df = src_df

    checklist_values = df['Checklist'].values
    description_values = df['Description'].values
    type_values = df['Type'].values
    no_values = df['Index'].values
    reg_path_values = df['Reg Key'].values
    reg_item_values = df['Reg Item'].values
    value_data_values = df['Value Data'].values
    subcategory_values = df['Audit Policy Subcategory'].values

    actual_value_list = []
    result_lists = []

    for idx, val in enumerate(checklist_values):
        if val == 1:
            rule_type = str(type_values[idx])

            if rule_type == "REGISTRY_SETTING" or rule_type == "BANNER_CHECK":

                # continue
                path = str(reg_path_values[idx])
                name = str(reg_item_values[idx])
                expect_value = str(value_data_values[idx])

                if path.startswith("HK"):
                    actual_value = get_registry_value(path, name)
                    actual_value_list.append(actual_value)
                    print(
                        f"{no_values[idx]}: The actual value is: {actual_value}")

                    if expect_value == str(actual_value):
                        print("Pass")
                        result_lists.append("Pass")
                    else:
                        print("Fail")
                        result_lists.append("Fail")
                else:
                    actual_value_list.append("")
                    result_lists.append("")

            elif rule_type == "AUDIT_POLICY_SUBCATEGORY":
                # actual_value_list.append("")
                # result_lists.append("")
                # continue
                subcategory = str(subcategory_values[idx])
                expect_value = str(value_data_values[idx])

                print(subcategory)
                actual_value = get_audit_policy(subcategory)
                actual_value_list.append(actual_value)
                print(f"{no_values[idx]}: The actual value is: {actual_value}")

                # compare result vs expected_value
                if actual_value == "":
                    result_lists.append("")
                    continue

                result = compare_audit_result(actual_value, expect_value)
                result_lists.append(result)
            elif rule_type == "REG_CHECK":

                if no_values[idx] == "18.9.19.5":
                    # path = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
                    path = value_data_values[idx]
                    # name = 'DisableBkGndGroupPolicy'
                    name = str(reg_item_values[idx])
                    actual_value = get_registry_value(path, name)
                    actual_value_list.append(actual_value)
                    print(
                        f"{no_values[idx]}: The actual value is: {actual_value}")
                    if actual_value == "Value Not found" or actual_value == "Disabled":
                        print("Pass")
                        result_lists.append("Pass")
                    else:
                        print("Fail")
                        result_lists.append("Fail")

                else:
                    actual_value_list.append("")
                    result_lists.append("")

            elif rule_type == "PASSWORD_POLICY":

                description = str(description_values[idx])
                expect_value = str(value_data_values[idx])

                if "Enforce password history" in description:
                    actual_value = get_pwd_policy('PasswordHistorySize')
                    actual_value_list.append(actual_value)
                    print(
                        f"{no_values[idx]}: The actual value is: {actual_value}")

                    try:
                        actual_value = int(actual_value)
                    except ValueError:
                        print(f"Invalid value: {actual_value}")
                        result_lists.append("Fail")

                    if actual_value >= int(expect_value):
                        print("Pass")
                        result_lists.append("Pass")
                    else:
                        print("Fail")
                        result_lists.append("Fail")

                elif "Maximum password age" in description:
                    actual_value = get_pwd_policy('MaximumPasswordAge')
                    actual_value_list.append(actual_value)
                    print(
                        f"{no_values[idx]}: The actual value is: {actual_value}")

                    try:
                        actual_value = int(actual_value)
                    except ValueError:
                        print(f"Invalid value: {actual_value}")
                        result_lists.append("Fail")

                    if actual_value > 0 and actual_value <= int(expect_value):
                        print("Pass")
                        result_lists.append("Pass")
                    else:
                        print("Fail")
                        result_lists.append("Fail")

                elif "Minimum password age" in description:
                    actual_value = get_pwd_policy('MinimumPasswordAge')
                    actual_value_list.append(actual_value)
                    print(
                        f"{no_values[idx]}: The actual value is: {actual_value}")

                    try:
                        actual_value = int(actual_value)
                    except ValueError:
                        print(f"Invalid value: {actual_value}")
                        result_lists.append("Fail")

                    if actual_value >= int(expect_value):
                        print("Pass")
                        result_lists.append("Pass")
                    else:
                        print("Fail")
                        result_lists.append("Fail")

                elif "Minimum password length" in description:
                    actual_value = get_pwd_policy('MinimumPasswordLength')
                    actual_value_list.append(actual_value)
                    print(
                        f"{no_values[idx]}: The actual value is: {actual_value}")

                    try:
                        actual_value = int(actual_value)
                    except ValueError:
                        print(f"Invalid value: {actual_value}")
                        result_lists.append("Fail")

                    if actual_value >= int(expect_value):
                        print("Pass")
                        result_lists.append("Pass")
                    else:
                        print("Fail")
                        result_lists.append("Fail")

                elif "complexity requirements" in description:
                    actual_value = get_pwd_policy('PasswordComplexity')
                    actual_value_list.append(actual_value)
                    print(
                        f"{no_values[idx]}: The actual value is: {actual_value}")

                    try:
                        actual_value = int(actual_value)
                    except ValueError:
                        print(f"Invalid value: {actual_value}")
                        result_lists.append("Fail")

                    if actual_value == int(expect_value):
                        print("Pass")
                        result_lists.append("Pass")
                    else:
                        print("Fail")
                        result_lists.append("Fail")

                elif "reversible encryption" in description:
                    actual_value = get_pwd_policy('ClearTextPassword')
                    actual_value_list.append(actual_value)
                    print(
                        f"{no_values[idx]}: The actual value is: {actual_value}")

                    try:
                        actual_value = int(actual_value)
                    except ValueError:
                        print(f"Invalid value: {actual_value}")
                        result_lists.append("Fail")

                    if actual_value == int(expect_value):
                        print("Pass")
                        result_lists.append("Pass")
                    else:
                        print("Fail")
                        result_lists.append("Fail")

                elif "Administrator account lockout" in description:
                    actual_value_list.append("")
                    result_lists.append("Manual")

                elif "Force logoff when logon hours expire" in description:
                    actual_value = get_pwd_policy('ForceLogoffWhenHourExpire')
                    actual_value_list.append(actual_value)
                    print(
                        f"{no_values[idx]}: The actual value is: {actual_value}")

                    try:
                        actual_value = int(actual_value)
                    except ValueError:
                        print(f"Invalid value: {actual_value}")
                        result_lists.append("Fail")

                    if actual_value == int(expect_value):
                        print("Pass")
                        result_lists.append("Pass")
                    else:
                        print("Fail")
                        result_lists.append("Fail")

                else:
                    actual_value_list.append("")
                    result_lists.append("")

            elif rule_type == "ANONYMOUS_SID_SETTING":

                description = str(description_values[idx])
                expect_value = str(value_data_values[idx])

                if "Allow anonymous SID/Name translation" in description:
                    actual_value = get_pwd_policy('LSAAnonymousNameLookup')
                    actual_value_list.append(actual_value)
                    print(
                        f"{no_values[idx]}: The actual value is: {actual_value}")

                    try:
                        actual_value = int(actual_value)
                    except ValueError:
                        print(f"Invalid value: {actual_value}")
                        result_lists.append("Fail")

                    if actual_value == int(expect_value):
                        print("Pass")
                        result_lists.append("Pass")
                    else:
                        print("Fail")
                        result_lists.append("Fail")
                else:
                    actual_value_list.append("")
                    result_lists.append("")

            elif rule_type == "LOCKOUT_POLICY":
                description = str(description_values[idx])
                expect_value = str(value_data_values[idx])

                if "Account lockout duration" in description:
                    actual_value = get_lockout_policy("Lockout duration")
                    actual_value_list.append(actual_value)
                    print(
                        f"{no_values[idx]}: The actual value is: {actual_value}")

                    try:
                        actual_value = int(actual_value)
                    except ValueError:
                        print(f"Invalid value: {actual_value}")
                        result_lists.append("Fail")
                        continue

                    if actual_value >= int(expect_value):
                        print("Pass")
                        result_lists.append("Pass")
                    else:
                        print("Fail")
                        result_lists.append("Fail")

                elif "Account lockout threshold" in description:
                    actual_value = get_lockout_policy("Lockout threshold")
                    actual_value_list.append(actual_value)
                    print(
                        f"{no_values[idx]}: The actual value is: {actual_value}")

                    if actual_value == "Never":
                        print("Fail")
                        result_lists.append("Fail")

                    else:
                        try:
                            actual_value = int(actual_value)
                        except ValueError:
                            print(f"Invalid value: {actual_value}")
                            result_lists.append("Fail")
                            continue

                        if actual_value > 0 and actual_value <= int(expect_value):
                            print("Pass")
                            result_lists.append("Pass")
                        else:
                            print("Fail")
                            result_lists.append("Fail")

                elif "Reset account lockout counter" in description:
                    actual_value = get_lockout_policy(
                        "Lockout observation window")
                    actual_value_list.append(actual_value)
                    print(
                        f"{no_values[idx]}: The actual value is: {actual_value}")

                    try:
                        actual_value = int(actual_value)
                    except ValueError:
                        print(f"Invalid value: {actual_value}")
                        result_lists.append("Fail")
                        continue

                    if actual_value >= int(expect_value):
                        print("Pass")
                        result_lists.append("Pass")
                    else:
                        print("Fail")
                        result_lists.append("Fail")
                else:
                    actual_value_list.append("")
                    result_lists.append("")

            elif rule_type == "CHECK_ACCOUNT":

                description = str(description_values[idx])
                expect_value = str(value_data_values[idx])

                if "Guest account status" in description:
                    actual_value = get_guest_account("Account active")
                    actual_value_list.append(actual_value)
                    print(
                        f"{no_values[idx]}: The actual value is: {actual_value}")

                    try:
                        actual_value = int(actual_value)
                    except ValueError:
                        print(f"Invalid value: {actual_value}")
                        result_lists.append("Fail")
                        continue

                    if actual_value >= int(expect_value):
                        print("Pass")
                        result_lists.append("Pass")
                    else:
                        print("Fail")
                        result_lists.append("Fail")

                elif "Rename administrator account" in description:
                    actual_value = get_guest_account("User name")
                    actual_value_list.append(actual_value)
                    print(
                        f"{no_values[idx]}: The actual value is: {actual_value}")

                    try:
                        actual_value = int(actual_value)
                    except ValueError:
                        print(f"Invalid value: {actual_value}")
                        result_lists.append("Fail")
                        continue

                    if actual_value != int(expect_value):
                        print("Pass")
                        result_lists.append("Pass")
                    else:
                        print("Fail")
                        result_lists.append("Fail")

                elif "Rename guest account" in description:
                    actual_value = get_guest_account("User name")
                    actual_value_list.append(actual_value)
                    print(
                        f"{no_values[idx]}: The actual value is: {actual_value}")

                    try:
                        actual_value = int(actual_value)
                    except ValueError:
                        print(f"Invalid value: {actual_value}")
                        result_lists.append("Fail")
                        continue

                    if actual_value != int(expect_value):
                        print("Pass")
                        result_lists.append("Pass")
                    else:
                        print("Fail")
                        result_lists.append("Fail")
                else:
                    actual_value_list.append("")
                    result_lists.append("")

            else:
                actual_value_list.append("")
                result_lists.append("")
                continue

        else:
            actual_value_list.append("")
            result_lists.append("")
            continue

    df['actrual_value'] = actual_value_list
    df['result'] = result_lists

    return df


def read_file(fname):
    xl = pd.ExcelFile(fname)
    df = xl.parse(sheet_name=0)
    return df


def save_file(df, out_fname):
    # output a new CSV file
    df.to_csv(out_fname, index=False)
    print(f"Result saved into {out_fname}")


if __name__ == '__main__':
    checkOS()

    src_fname = 'src\win10_v6.xlsx'
    src_df = read_file(src_fname)

    output_df = check_result(src_df)

    out_fname = "out\output6.csv"
    save_file(src_df, out_fname)
