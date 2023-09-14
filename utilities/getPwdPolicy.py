import configparser
import subprocess
import os

from pypsexec.client import Client


def get_pwd_policy_local(subcategory):

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
    password_complexity = config.get('System Access', subcategory)

    return password_complexity


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

        # if val == 1

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
            result_lists.append("MANUAL")
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
                f"{ip_addr} | {idx_values[idx]}: PASSED | Expected: {expected_value} | Actual: {actual_value}")
            result_lists.append("PASSED")
        else:
            print(
                f"{ip_addr} | {idx_values[idx]}: FAILED | Expected: {expected_value} | Actual: {actual_value}")
            result_lists.append("FAILED")

        # else:
        #     actual_value_list.append("")
        #     result_lists.append("")

    col_name1 = ip_addr + ' | Actual Value'
    col_name2 = ip_addr + ' | Result'

    df[col_name1] = actual_value_list
    df[col_name2] = result_lists

    return df


def get_pwd_policy_actual_value(args_list, ip):
    max_attempts = 5
    for attempt in range(max_attempts):
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

            break

        except Exception as e:
            print(f"{ip[0]} | Error: {e}")
            print(f"Tried {attempt+1} times")

        finally:
            win_client.remove_service()
            win_client.disconnect()

    actual_value_list = actual_values.split("====")
    actual_value_list.pop(0)
    return actual_value_list


def compare_pwd_policy_local(data_dict):
    # password policy
    df = data_dict["PASSWORD_POLICY"]
    checklist_values = df['Checklist'].values
    description_values = df['Description'].values
    idx_values = df['Index'].values
    value_data_values = df['Value Data'].values
    actual_value_list = df['Actual Value'].values

    result_lists = []

    for idx, val in enumerate(checklist_values):

        pass_result = True

        # if val == 1

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
            result_lists.append("MANUAL")
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

        elif "Enforce user logon restrictions" in description:
            try:
                actual_value = int(actual_value)
                if actual_value == int(expected_value):
                    pass_result = True
                else:
                    pass_result = False
            except ValueError:
                print(f"Invalid value: {actual_value}")
                pass_result = False

        elif "Maximum lifetime for service ticket" in description or "Maximum lifetime for user ticket" in description or "Maximum lifetime for user ticket renewal" in description:
            try:
                actual_value = int(actual_value)
                vals = expected_value.strip("[]").split("..")
                min_val = vals[0]
                max_val = vals[1]

                if int(actual_value) >= int(min_val) and int(actual_value) <= int(max_val):
                    pass_result = True
                else:
                    pass_result = False
            except ValueError:
                print(f"Invalid value: {actual_value}")
                pass_result = False

        elif "Maximum tolerance for computer clock synchronization" in description:
            try:
                actual_value = int(actual_value)
                vals = expected_value.strip("[]").split("..")
                max_val = vals[1]

                if int(actual_value) <= int(max_val):
                    pass_result = True
                else:
                    pass_result = False

            except ValueError:
                pass_result = False

        else:
            pass_result = False

        if pass_result:
            print(
                f" {idx_values[idx]}: PASSED | Expected: {expected_value} | Actual: {actual_value}")
            result_lists.append("PASSED")
        else:
            print(
                f"{idx_values[idx]}: FAILED | Expected: {expected_value} | Actual: {actual_value}")
            result_lists.append("FAILED")

    col_name1 = "ip_addr" + ' | Actual Value'
    col_name2 = "ip_addr" + ' | Result'

    df = df.rename(columns={'Actual Value': col_name1})
    df[col_name1] = actual_value_list
    df[col_name2] = result_lists

    return df
