import winreg

def get_registry_value(path, name):
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
    value, regtype = winreg.QueryValueEx(key, name)
    winreg.CloseKey(key)
    return value

path = r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
# print(path)
name = "scremoveoption"
value = get_registry_value(path, name)

print(f"The value is: {value}")