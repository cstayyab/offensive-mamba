from CannonPlug import CannonPlug
import sys, os
import configparser
from configparser import ConfigParser
from SystemScan import SystemScan
from util import Utility
from __const import FAIL
from MetasploitCannon import MetasploitCannon

class CannonEngine:
    def __init__(self):
        self.cannons = {}
        self.tactics={}
        self.ips = []
        self.scaninfo = {}
        self.util = Utility()
        self.shells = {}
    def registerCannonPlug(self, plug: CannonPlug):
        tactics = plug.getSupportedAttackTactics()
        for tactic in tactics:
            if not (tactic in self.tactics):
                self.tactics[tactic] = []
            for mod in plug.getModulesForTactics(tactic):
                self.tactics[tactic].append([type(plug).__name__, mod])
        self.cannons[type(plug).__name__] = globals()[type(plug).__name__]
    def getAllRegisteredTechniques(self):
        return list(self.tactics.keys())
    def registerIP(self, ipaddr:str):
        u = Utility()
        if not u.isValidIP(ipaddr):
            raise ValueError("Invalid IP Address")
        if not (ipaddr in self.ips):
            self.ips.append(ipaddr)
    def gatherInformation(self, ipaddr: str):
        if not (ipaddr in self.ips):
            raise ValueError("IP Address must already be registered.")
        self.scaninfo[ipaddr] = SystemScan(ipaddr)
        self.scaninfo[ipaddr].startScan()
    def getSession(self, ipaddr: str):
        # TA0001 : Initial Access
        if not ("TA0001" in self.getAllRegisteredTechniques()):
            self.util.print_message(FAIL, "No Initial Access Modules are registered. Cannot Continue.")
            return False
        if not (self.scaninfo[ipaddr]):
            self.util.print_message(FAIL, "No Scan info for host: " + ipaddr + "! Cannot Continue.")
            return False
        
        tactics = self.tactics['TA0001']
        for t in tactics:
            cannon = self.cannons[t[0]]()
            targets = self.scaninfo[ipaddr].cpes
            print(targets)
            for target in targets:
                print(target)
                shell = cannon.fireModule(t[1], target['host'], int(target['port']))
                if(shell is not None):
                    self.shells[ipaddr] = shell
                    return True
        return False
                
