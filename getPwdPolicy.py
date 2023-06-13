import configparser
import subprocess
import os

def get_pwd_policy(subcategory):

    subprocess.run('secedit /export /cfg %temp%\\secpol.cfg /areas SECURITYPOLICY', shell=True, check=True)

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

print("result:",get_pwd_policy('PasswordHistorySize'))
