
# from Metasploit import Metasploit
# from CPEs import parseCPEs
from pycvesearch import CVESearch
from SystemScan import SystemScan

cve = CVESearch()
#env = Metasploit('210.56.28.244')
# env = Metasploit('172.28.128.3') # Replace with NMAP Library so as to use other Metasploit Module
# nmap_result = 'nmap_result_' + env.rhost + '.xml'
# nmap_command = env.nmap_command + ' ' + nmap_result + ' ' + env.rhost + '\n'
# env.execute_nmap(env.rhost, nmap_command, env.nmap_timeout)
# com_port_list, proto_list, info_list = env.get_port_list(nmap_result, env.rhost)
# for port, info in zip(com_port_list, info_list):
#     print(port + " [" + info + "]" )
sc = SystemScan('172.28.128.3')
sc.startScan()
sc.fetchMSFE()
# cpes = sc.cpes
# msfmodules = []
# for c in cpes:
#     if(c['cpe'].startswith("cpe:/o")):
#         continue
#     exploits = []
#     cvedata = cve.cvefor(c['cpe'])
#     for vdata in cvedata:
#         if 'metasploit' in vdata:
#             for e in vdata['metasploit']:
#                 exploits.append(e['id'][4:].lower())
#     c['metasploit'] = exploits
#     print(c)

