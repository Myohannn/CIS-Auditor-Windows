import pandas as pd
import winreg
import platform
import subprocess


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

        if output is "":
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


def check_result(src_df):
    df = src_df

    checklist_values = df['Checklist'].values
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

                if actual_value == "":
                    result_lists.append("")
                    continue


                result = compare_audit_result(actual_value, expect_value)
                result_lists.append(result)

                # compare result vs expected_value
            
            
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
            elif rule_type == "PASSWORD_POLICY":
                print()
            
            
            
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

    src_fname = 'src\win10_v4.xlsx'
    src_df = read_file(src_fname)

    output_df = check_result(src_df)

    out_fname = "out\output3.csv"
    save_file(src_df, out_fname)
