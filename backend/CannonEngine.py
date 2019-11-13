from CannonPlug import CannonPlug
import sys, os
import configparser
from configparser import ConfigParser
from SystemScan import SystemScan
from util import Utility

class CannonEngine:
    def __init__(self):
        self.cannons = {}
        self.techniques={}
        self.ips = []
        self.scaninfo = {}
    def registerCannonPlug(self, plug: CannonPlug):
        techs = plug.getSupportedAttackTechniques()
        for tech in techs:
            if not (tech in self.techniques):
                self.techniques[tech] = []
            for mod in plug.getModulesForTechniques(tech):
                self.techniques[tech].append([type(plug).__name__, mod])
    def getAllRegisteredTechniques(self):
        return list(self.techniques.keys())
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
        pass