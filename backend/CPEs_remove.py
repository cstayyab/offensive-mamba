import requests
from lxml import html
import xml.etree.ElementTree as treant
import warnings
from util import Utilty
from __const import *

warnings.simplefilter("ignore")

def banner():
    pass

def parserResponse(content,limit):
    tree = html.fromstring(content)
    desc = tree.xpath("//*[contains(@data-testid, 'vuln-summary')]")
    cve = tree.xpath("//*[contains(@data-testid, 'vuln-detail-link')]")
    score = tree.xpath("//*[contains(@data-testid, 'vuln-cvss2-link')]")
    if len(desc) > 0:
        maxLimit = limit if limit <= len(desc) else len(desc) - 1
        for i in range(0,maxLimit):
            print("\t\t%s" % desc[i].text)
            print("\t\t%s" % cve[i].text)
            print("\t\t%s" % score[i].text)
            print()
    print()

def getCPE(cpe):
    url = 'https://nvd.nist.gov/vuln/search/results?adv_search=true&cpe=%s' % cpe
    r = requests.get(url)
    if r.status_code == 200:
        return r.content
    else:
        return False

def fix_cpe_str(str):
    return str.replace('-',':')

def parseCPEs(filenmap):
    tree = treant.parse(filenmap)
    root = tree.getroot()
    cpeinfo = []
    u = Utilty()
    for child in root.findall('host'):
        for k in child.findall('address'):
            host = k.attrib['addr']
            for y in child.findall('ports/port'):
                current_port = y.attrib['portid']
                for z in y.findall('service/cpe'):
                    if len(z.text) > 4:
                        cpe = fix_cpe_str(z.text)
                        # print("\n::::: Vision v0.1 - nmap NVD's cpe correlation \n")
                        # print("Host: %s" % host)
                        # print("Port: %s" % current_port)
                        # print("cpe: %s" % cpe)
                        u.print_message(OK , "Found CPE: " + cpe + " on port " + current_port + " of Host " + host)
                        cpeinfo.append({"host": host, "port": current_port, "cpe": cpe })
    return cpeinfo
