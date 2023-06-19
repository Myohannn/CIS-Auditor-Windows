import winreg
from pypsexec.client import Client

win_client = Client("192.168.56.103", username="vboxuser", password="AskDNV8!")
win_client.connect()


def get_registry_value_local(path, name):
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
    value, regtype = winreg.QueryValueEx(key, name)
    winreg.CloseKey(key)
    return value


def get_registry_value(reg_key, reg_item):
    global win_client

    try:
        win_client.create_service()
        # args = "-command \"Get-ItemPropertyValue -Path 'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion' -Name 'ProductName'\""
        args = f"-command Get-ItemPropertyValue -Path '{reg_key}' -Name '{reg_item}'"

        stdout, stderr, rc = win_client.run_executable(
            "powershell.exe", arguments=args)

        output = stdout.decode("utf-8").strip()  # Convert bytes to string
        stderr = stderr.decode("utf-8")
        # print(f"Output: {output}")
        # print(f"Error: {stderr}")
        # print(f"Exit Code: {rc}")
    finally:
        win_client.remove_service()
        win_client.disconnect()
        return output


# path = r"HKLM\Software\Microsoft\Windows Nt\Currentversion"
# # print(path)
# name = "ProductName"
reg_key = r"HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
reg_item = "RequireSignOrSeal"
value = get_registry_value(reg_key, reg_item)

print(f"The value is: {value}!")
print(value =='1')
