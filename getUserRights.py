import configparser
import subprocess
import os

def get_user_right(subcategory):

    subprocess.run('secedit /export /cfg %temp%\\secpol.cfg /areas user_rights', shell=True, check=True)

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

print("result:",get_user_right('SeNetworkLogonRight'))
