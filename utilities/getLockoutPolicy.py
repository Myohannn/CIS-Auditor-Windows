import subprocess
from pypsexec.client import Client


def get_lockout_policy(policy_name):
    command = 'net accounts'
    output = subprocess.check_output(command, shell=True).decode()
    output_lines = output.split("\n")

    for line in output_lines:
        if policy_name in line:

            return line.strip().split()[-1]


def get_value():
    try:
        win_client = Client("", username="", password="")
        win_client.connect()
        win_client.create_service()

        arg = "net accounts"

        stdout, stderr, rc = win_client.run_executable(
            "powershell.exe", arguments=arg)

        output = stdout.decode("utf-8").split('\r\n')

        print(f"Output:\n{output}")
    finally:
        win_client.remove_service()
        win_client.disconnect()
        # return result
        # return result

    args_list = ["Lockout duration", "Lockout threshold"]
    actual_value_list = []
    for arg in args_list:
        for out in output:
            if arg in out:
                actual_value_list.append(out.split()[-1].strip())

    print(actual_value_list)


def get_lockout_policy_actual_value(args_list, ip):
    actual_value_list = []

    max_attempts = 5
    for attempt in range(max_attempts):
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
            break

        except Exception as e:
            print(f"{ip[0]} | Error: {e}")
            print(f"Tried {attempt+1} times")
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

        # if val == 1

        description = description_values[idx]
        expected_value = str(value_data_values[idx]).lower()
        actual_value = actual_value_list[idx]

        if "Account lockout duration" in description:
            try:
                actual_value = int(actual_value)
                vals = expected_value.strip("[]").split("..")
                min_val = vals[0]

                if int(actual_value) >= int(min_val):
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
                    vals = expected_value.strip("[]").split("..")
                    min_val = vals[0]
                    max_val = vals[1]

                    if int(actual_value) >= int(min_val) and int(actual_value) <= int(max_val):
                        pass_result = True
                    else:
                        pass_result = False

                except ValueError:
                    pass_result = False
        elif "Reset account lockout counter" in description:
            try:
                actual_value = int(actual_value)
                vals = expected_value.strip("[]").split("..")
                min_val = vals[0]
                max_val = vals[1]

                if int(actual_value) >= int(min_val):
                    pass_result = True
                else:
                    pass_result = False

            except ValueError:
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

    # data_dict["LOCKOUT_POLICY"] = df
    return df


def compare_lockout_policy_local(data_dict):
    # password policy
    df = data_dict["LOCKOUT_POLICY"]
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
        actual_value = actual_value_list[idx].split()[-1].strip()
        actual_value_list[idx] = actual_value

        if "Account lockout duration" in description:
            try:
                actual_value = int(actual_value)
                vals = expected_value.strip("[]").split("..")
                min_val = vals[0]

                if int(actual_value) >= int(min_val):
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
                    vals = expected_value.strip("[]").split("..")
                    min_val = vals[0]
                    max_val = vals[1]

                    if int(actual_value) >= int(min_val) and int(actual_value) <= int(max_val):
                        pass_result = True
                    else:
                        pass_result = False

                except ValueError:
                    pass_result = False
        elif "Reset account lockout counter" in description:
            try:
                actual_value = int(actual_value)
                vals = expected_value.strip("[]").split("..")
                min_val = vals[0]
                max_val = vals[1]

                if int(actual_value) >= int(min_val):
                    pass_result = True
                else:
                    pass_result = False

            except ValueError:
                pass_result = False
        else:
            pass_result = False

        if pass_result:
            print(
                f"{idx_values[idx]}: PASSED | Expected: {expected_value} | Actual: {actual_value}")
            result_lists.append("PASSED")
        else:
            print(
                f"{idx_values[idx]}: FAILED | Expected: {expected_value} | Actual: {actual_value}")
            result_lists.append("FAILED")

        # else:
        #     actual_value_list.append("")
        #     result_lists.append("")

    col_name1 = 'ip_addr' + ' | Actual Value'
    col_name2 = 'ip_addr' + ' | Result'

    df = df.rename(columns={'Actual Value': col_name1})
    df[col_name1] = actual_value_list
    df[col_name2] = result_lists

    # data_dict["LOCKOUT_POLICY"] = df
    return df
