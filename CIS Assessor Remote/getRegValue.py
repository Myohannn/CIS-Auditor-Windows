import winreg
from pypsexec.client import Client

# Record the start time


def get_registry_value_local(path, name):
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
    value, regtype = winreg.QueryValueEx(key, name)
    winreg.CloseKey(key)
    return value


def get_registry_value_list(args_list):

    try:
        win_client = Client("", username="", password="")
        win_client.connect()
        win_client.create_service()
        # args = "-command \"Get-ItemPropertyValue -Path 'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion' -Name 'ProductName'\""
        # args = f"-command Get-ItemPropertyValue -Path '{reg_key}' -Name '{reg_item}'"

        result = ''

        if args_list == ['']:
            return ['']

        for arg in args_list:
            # print(arg)
            stdout, stderr, rc = win_client.run_executable(
                "powershell.exe", arguments=arg)

            output = stdout.decode("utf-8").replace('\r\n', '')
            result = result + output

        print("here1")
    finally:

        win_client.remove_service()
        win_client.disconnect()
        return result


def get_reg_value(ip, reg_key, reg_item):
    try:
        win_client = Client(
            ip[0], username=ip[1], password=ip[2])
        win_client.connect()
        win_client.create_service()
        arg = f'''
        Get-ItemPropertyValue -Path '{reg_key}' -Name '{reg_item}'
        '''
        stdout, stderr, rc = win_client.run_executable(
            "powershell.exe", arguments=arg)

        output = stdout.decode("utf-8").replace('\r\n', '')

    finally:
        win_client.remove_service()
        win_client.disconnect()
        return output


def compare_reg_value(ip_addr, actual_value_list, data_dict):

    # registry value
    df = data_dict["REGISTRY_SETTING"]
    checklist_values = df['Checklist'].values
    idx_values = df['Index'].values
    value_data_values = df['Value Data'].values
    reg_option = df['Reg Option'].values

    # actual_value_list = actual_value_dict["REGISTRY_SETTING"]
    result_lists = []

    for idx, val in enumerate(checklist_values):

        pass_result = False

        if val == 1:

            expected_value = str(value_data_values[idx]).lower()

            if actual_value_list[idx] == "":
                actual_value_list[idx] = "Null"

            actual_value = actual_value_list[idx].lower()

            if actual_value == 'null':
                if idx_values[idx] == "2.3.10.6" or idx_values[idx] == "5.7" or reg_option[idx] == 'CAN_BE_NULL':
                    pass_result = True
            else:
                if idx_values[idx] == "2.3.10.7" or idx_values[idx] == "2.3.10.8":
                    expected_value = expected_value.lower().split(" && ")[
                        0].strip()
                    actual_value = [s.lower() for s in actual_value]

                    actual_value = ''.join(actual_value)

                    if expected_value == actual_value:
                        pass_result = True

                elif "||" in expected_value:
                    expected_value = expected_value.split(" || ")
                    if str(actual_value) in expected_value:
                        pass_result = True

                elif "[" in expected_value:
                    vals = expected_value.strip("[]").split("..")
                    min_val = vals[0]
                    max_val = vals[1]

                    if min_val == "min":
                        if int(actual_value) <= int(max_val):
                            pass_result = True
                    elif max_val == "max":
                        if int(actual_value) >= int(min_val):
                            pass_result = True
                    else:
                        if int(actual_value) >= int(min_val) and int(actual_value) <= int(max_val):
                            pass_result = True

                else:
                    if str(expected_value) == str(actual_value):
                        pass_result = True

            if pass_result:
                print(
                    f"{ip_addr} | {idx_values[idx]}: PASSED | Expected: {expected_value} | Actual: {actual_value}")
                result_lists.append("PASSED")
            else:
                print(
                    f"{ip_addr} | {idx_values[idx]}: FAILED | Expected: {expected_value} | Actual: {actual_value}")
                result_lists.append("FAILED")

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

    max_attempts = 5
    for attempt in range(max_attempts):

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

            break

        except Exception as e:
            print("{ip[0]} | Error: %s", e)
            print(f"Tried {attempt+1} times")

        finally:
            win_client.remove_service()
            win_client.disconnect()
            # return actual_values

    actual_value_list = actual_values.split("====")
    actual_value_list.pop(0)

    return actual_value_list
