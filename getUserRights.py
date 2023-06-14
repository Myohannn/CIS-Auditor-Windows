import configparser
import subprocess
import os


def get_user_right(subcategory):

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

# print("result:",get_user_right('SeNetworkLogonRight'))



def compare_user_right(right_type, expected_value, actual_value):
    user_right_dict = {"":"",
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

expected_value = "Administrators"
actual_value = "*S-1-5-32-544,*S-1-5-32-551"
right_type = 'SeCreateSymbolicLinkPrivilege'
print(compare_user_right(right_type, expected_value, actual_value))


# d = "locAl aCcount"
# sid = subprocess.run(f'-Command (New-Object -TypeName System.Security.Principal.NTAccount("{d}")).Translate([System.Security.Principal.SecurityIdentifier]).Value', shell=True, check=True)


def get_sid(username):
    cmd = f'(New-Object -TypeName System.Security.Principal.NTAccount("{username}")).Translate([System.Security.Principal.SecurityIdentifier]).Value'
    result = subprocess.run(
        ["powershell", "-Command", cmd], capture_output=True)
    return result.stdout.decode().strip()


# username = "NETWORK SERVICE"
# sid = get_sid(username)
# print(sid)
