import subprocess
from pypsexec.client import Client


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


def get_value():
    try:
        win_client = Client(
            "", username="", password="")
        win_client.connect()
        win_client.create_service()

        arg = "net user guest"

        stdout, stderr, rc = win_client.run_executable(
            "powershell.exe", arguments=arg)

        output = stdout.decode("utf-8").split('\r\n')

        print(f"Output:\n{output}")
    finally:
        win_client.remove_service()
        win_client.disconnect()


def get_check_account_actual_value(args_list, ip):
    actual_value_list = []

    max_attempts = 5
    for attempt in range(max_attempts):

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

            break

        except Exception as e:
            print(f"{ip[0]} | Error: {e}")
            print(f"Tried {attempt+1} times")

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

    # data_dict["CHECK_ACCOUNT"] = df
    return df
