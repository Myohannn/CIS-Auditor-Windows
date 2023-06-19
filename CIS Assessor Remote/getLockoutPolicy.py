import subprocess

def get_lockout_policy(policy_name):
    command = 'net accounts'
    output = subprocess.check_output(command, shell=True).decode()
    output_lines = output.split("\n")

    for line in output_lines:
        if policy_name in line:

            return line.strip().split()[-1]

# print(get_lockout_policy())