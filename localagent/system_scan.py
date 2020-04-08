import os
import sys
import tempfile
import configparser
import nmap
from util import Utility
from __const import FAIL, NOTE

# from pycvesearch import CVESearch

class SystemScan:
    def __init__(self, ip_addr='127.0.0.1'):
        self.ip_address = ip_addr
        self.scanner = nmap.PortScanner()
        self.xml = None
        self.util = Utility()

        # Read Configuration Options
        full_dir_path = os.path.dirname(os.path.abspath(__file__))
        config = configparser.ConfigParser()
        try:
            config.read(os.path.join(full_dir_path, 'config.ini'))
        except FileExistsError:
            self.util.print_message(FAIL, 'Configuration file missing. exiting...')
            sys.exit(1)
        self.nmap_arguments = config['Nmap']['command'][5:]

        # self.cpes = None
        # self.OScpe = []
        # self.cve = CVESearch()

    def start_scan(self):
        self.util.print_message(NOTE, "Starting NMAP Scan for Host " + self.ip_address + ". It will take some time to complete. Please be patient...")
        self.scanner.scan(self.ip_address, arguments=self.nmap_arguments)
        self.xml = self.scanner.get_nmap_last_output()
        self.util.print_message(NOTE, "Scan completed for Host " + self.ip_address)
    
    def get_xml_in_file(self):
        fd, fname = tempfile.mkstemp( suffix=".xml", prefix="nmap_")
        os.write(fd, bytes(self.xml, "utf-8"))
        os.close(fd)
        return fname

if __name__ == "__main__":
    n = SystemScan("115.186.176.141")
    n.start_scan()
    f = n.get_xml_in_file()
    print(f)
    print(open(f, "r").read())
        

        

    # def fetchMSFE(self):
    #     self.OScpe = []
    #     root = treant.fromstring(self.xml)
    #     cpeinfo = []
    #     u = Utility()
    #     for child in root.findall('host'):
    #         for k in child.findall('address'):
    #             host = k.attrib['addr']
    #             for y in child.findall('ports/port'):
    #                 current_port = y.attrib['portid']
    #                 for z in y.findall('service/cpe'):
    #                     if len(z.text) > 4:
    #                         cpe = z.text.replace('-',':')
    #                         u.print_message(OK , "Found CPE: " + cpe + " on port " + current_port + " of Host " + host)
    #                         if(cpe.startswith("cpe:/o")):
    #                             self.OScpe.append(cpe)
    #                             continue
    #                         msfe = []
    #                         cvedata = self.cve.cvefor(cpe)
    #                         for vdata in cvedata:
    #                             if 'metasploit' in vdata:
    #                                 for e in vdata['metasploit']:
    #                                     ex = e['id'][4:].lower()
    #                                     msfe.append(ex)
    #                                     u.print_message(WARNING, "Found Metasploit Exploit: " + ex)
    #                         if(len(msfe) == 0):
    #                             u.print_message(WARNING, "Cannot find any corresponding metasploit exploits.")
    #                         cpeinfo.append({"host": host, "port": current_port, "cpe": cpe, "msfe": msfe })
    #     self.cpes = cpeinfo
        
    




