import subprocess

# command = 'auditpol /get /subcategory:"Security Group Management"'
# process = subprocess.Popen(
#     command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
# output, error = process.communicate()

# if process.returncode != 0:
#     print(f"Error occurred: {error.decode()}")
# else:
#     print(output.decode())


def get_audit_policy(subcategory):
    cmd = f'auditpol /get /subcategory:"{subcategory}"'
    result = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    output = result.stdout
    print(f'result is {output}')

    line = output.split('\n')[4]
    result = line.replace(subcategory, '').strip()
    return result

print(get_audit_policy("Credential Validation"))

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


# actual_value, expected_value = "Success and Failure", "Success || Success, Failure"

# print(compare_audit_result(actual_value, expected_value))
