import winreg

def get_registry_value(path, name):
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
    value, regtype = winreg.QueryValueEx(key, name)
    winreg.CloseKey(key)
    return value

path = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
# print(path)
name = "LegalNoticeText"
value = get_registry_value(path, name)

print(f"The value is: {value}")
