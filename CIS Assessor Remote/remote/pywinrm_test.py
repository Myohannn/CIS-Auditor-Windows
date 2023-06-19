import winrm

ps_script = """net accounts"""

s = winrm.Session('192.168.56.103', auth=('vboxuser', 'AskDNV8!'))
r = s.run_ps(ps_script)