from pypsexec.client import Client

# creates an encrypted connection to the host with the username and password
win_client = Client("192.168.56.103", username="vboxuser", password="AskDNV8!")

win_client.connect()
try:
    win_client.create_service()
    key = "HKLM\Software\Microsoft\Windows Nt\Currentversion"
    args = '/c (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinServerSec").NTLMMinServerSec'

    stdout, stderr, rc = c.run_executable("powershell.exe", arguments=args)

    # print(f"Output: {stdout}")
    # print(f"Error: {stderr}")
    # print(f"Exit Code: {rc}")

    output = stdout.decode("utf-8")  # Convert bytes to string
    print(output)

finally:
    win_client.remove_service()
    win_client.disconnect()
