import nmap
import tempfile
import requests
from lxml import html
import xml.etree.ElementTree as treant
import warnings
from util import Utility
from __const import OK, NOTE, WARNING
from pycvesearch import CVESearch

class SystemScan:
    def __init__(self, ipAddr='127.0.0.1'):
        self.ip = ipAddr
        self.sc = nmap.PortScanner()
        self.xml = None
        self.cpes = None
        self.OScpe = []
        self.cve = CVESearch()

    def startScan(self):
        u = Utility()
        u.print_message(NOTE, "Starting NMAP Scan for Host " + self.ip)
        self.sc.scan(self.ip, arguments="-p0-65535 -T5 -Pn -sV -sT --min-rate 1000")
        self.xml = self.sc.get_nmap_last_output()
        u.print_message(OK, "Scan completed for Host " + self.ip)
        self.fetchMSFE()
        

    def fetchMSFE(self):
        self.OScpe = []
        root = treant.fromstring(self.xml)
        cpeinfo = []
        u = Utility()
        for child in root.findall('host'):
            for k in child.findall('address'):
                host = k.attrib['addr']
                for y in child.findall('ports/port'):
                    current_port = y.attrib['portid']
                    for z in y.findall('service/cpe'):
                        if len(z.text) > 4:
                            cpe = z.text.replace('-',':')
                            u.print_message(OK , "Found CPE: " + cpe + " on port " + current_port + " of Host " + host)
                            if(cpe.startswith("cpe:/o")):
                                self.OScpe.append(cpe)
                                continue
                            msfe = []
                            cvedata = self.cve.cvefor(cpe)
                            for vdata in cvedata:
                                if 'metasploit' in vdata:
                                    for e in vdata['metasploit']:
                                        ex = e['id'][4:].lower()
                                        msfe.append(ex)
                                        u.print_message(WARNING, "Found Metasploit Exploit: " + ex)
                            cpeinfo.append({"host": host, "port": current_port, "cpe": cpe, "msfe": msfe })
        self.cpes = cpeinfo
        
    




