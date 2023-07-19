import configparser
import subprocess
import os
from pypsexec.client import Client


def get_user_right_local(subcategory):

    subprocess.run(
        'secedit /export /cfg %temp%\\secpol.cfg /areas user_rights', shell=True, check=True)

    # Create a ConfigParser object
    config = configparser.ConfigParser()

    # Open the file in binary mode, read it, decode it and split it into lines
    with open(os.getenv('temp') + '\\secpol.cfg', 'rb') as f:
        content = f.read().decode('utf-16').split('\n')

    # Make ConfigParser read the lines
    config.read_string('\n'.join(content))

    # Get the value of PasswordComplexity
    result = config.get('Privilege Rights', subcategory)

    return result


def get_sid(username):
    cmd = f'(New-Object -TypeName System.Security.Principal.NTAccount("{username}")).Translate([System.Security.Principal.SecurityIdentifier]).Value'
    result = subprocess.run(
        ["powershell", "-Command", cmd], capture_output=True)
    return result.stdout.decode().strip()


print(get_sid("Window Manager"))


def get_user_rights_remote():
    try:

        win_client = Client("", username="", password="")
        win_client.connect()
        win_client.create_service()

        # dump all user rights
        arg = r"if (!(Test-Path -Path C:\temp )) { New-Item -ItemType directory -Path C:\temp };secedit /export /cfg C:\temp\secpol.cfg /areas user_rights"
        win_client.run_executable(
            "powershell.exe", arguments=arg)

        # get user rights value
        args_list = ["Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeTrustedCredManAccessPrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeNetworkLogonRight';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeTcbPrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeIncreaseQuotaPrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeInteractiveLogonRight';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeRemoteInteractiveLogonRight';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeBackupPrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeSystemTimePrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeTimeZonePrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeCreatePagefilePrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeCreateTokenPrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeCreateGlobalPrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeCreatePermanentPrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeCreateSymbolicLinkPrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeDebugPrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeDenyNetworkLogonRight';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeDenyBatchLogonRight';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeDenyServiceLogonRight';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeDenyInteractiveLogonRight';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeDenyRemoteInteractiveLogonRight';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeEnableDelegationPrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeRemoteShutdownPrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeAuditPrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeImpersonatePrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeIncreaseBasePriorityPrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeLoadDriverPrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeLockMemoryPrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeSecurityPrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeReLabelPrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeSystemEnvironmentPrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeManageVolumePrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeProfileSingleProcessPrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeSystemProfilePrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeAssignPrimaryTokenPrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeRestorePrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeShutdownPrivilege';Write-Output '===='; Get-Content -Path C:\\temp\\secpol.cfg | Select-String -Pattern 'SeTakeOwnershipPrivilege'"]
        result = ''
        # print(len(args_list))
        for arg in args_list:

            stdout, stderr, rc = win_client.run_executable(
                "powershell.exe", arguments=arg)

            output = stdout.decode("utf-8").replace('\r\n', '')
            result = result + output

    finally:
        win_client.remove_service()
        win_client.disconnect()
        return result


def get_user_rights_actual_value(args_list, ip):

    max_attempts = 5
    for attempt in range(max_attempts):

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

            break

        except Exception as e:
            print(f"{ip[0]} | Error: {e}")
            print(f"Tried {attempt+1} times")

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
                       "administrators": "*S-1-5-32-544",
                       "users": "*S-1-5-32-545",
                       "guests": "*S-1-5-32-546",
                       "remote desktop users": "*S-1-5-32-555",
                       "local service": "*S-1-5-19",
                       "network service": "*S-1-5-20",
                       "service": "*S-1-5-6",
                       "virtual machines": "*S-1-5-83-0",
                       "local account": "*S-1-5-113",
                       "window manager": "*S-1-5-90-0",
                       "window manager group": "*S-1-5-90-0",
                       "window manager\window manager group": "*S-1-5-90-0",
                       "nt service": "*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420",
                       "wdiservicehost": "*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420",
                       "nt service\wdiservicehost": "*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"}

    actual_set = set(actual_value.split(','))
    sid_set = set()
    sid_set_list = []

    if right_type == 'SeSyncAgentPrivilege':
        if actual_value == '':
            return True
        else:
            return False

    if '(' in expected_value or ')' in expected_value:

        if right_type == 'SeIncreaseBasePriorityPrivilege':
            sid_set_list.append(set([user_right_dict['administrators'],
                                user_right_dict["window manager\window manager group"]]))
        elif right_type == 'SeCreateSymbolicLinkPrivilege':
            sid_set_list.append(set([user_right_dict['administrators']]))
            sid_set_list.append(
                set([user_right_dict['administrators'], user_right_dict["virtual machines"]]))
        elif right_type == 'SeSystemProfilePrivilege':
            sid_set_list.append(set(
                [user_right_dict['administrators'], user_right_dict["nt service\wdiservicehost"]]))
        elif right_type == 'SeSecurityPrivilege':
            sid_set_list.append(set([user_right_dict['administrators']]))

    else:
        if '&' in expected_value:
            user_list = expected_value.split(" && ")
            for u in user_list:
                u = u.lower()
                sid_set.add(user_right_dict[u])

        elif '|' in expected_value:
            user_list = expected_value.split(" || ")
            for u in user_list:
                u = u.lower()
                sid_set.add(user_right_dict[u])
        else:
            sid_set.add(user_right_dict[expected_value.lower()])

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

        # if val == 1

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

    # data_dict["USER_RIGHTS_POLICY"] = df
    return df


def compare_user_rights_local(data_dict):
    # user rights
    df = data_dict["USER_RIGHTS_POLICY"]
    checklist_values = df['Checklist'].values
    idx_values = df['Index'].values
    value_data_values = df['Value Data'].values
    right_type_values = df['Right type'].values
    actual_value_list = df['Actual Value'].values

    # actual_value_list = actual_value_dict["USER_RIGHTS_POLICY"]
    result_lists = []

    for idx, val in enumerate(checklist_values):

        pass_result = True

        # if val == 1

        right_type = str(right_type_values[idx])
        expected_value = str(value_data_values[idx])
        actual_value = actual_value_list[idx].strip()
        actual_value = actual_value.split("=")[-1].strip()
        actual_value_list[idx] = actual_value

        try:
            # print("Goodd")
            result = True
            print(result)
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

    return df
