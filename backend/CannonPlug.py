class CannonPlug(object):
    def __init__(self):
        self.enterpriseTactics = {
            "TA0001" : "Initial Access",
            "TA0002" : "Execution",
            "TA0003" : "Persistence",
            "TA0004" : "Privilege Escalation",
            "TA0005" : "Defense Evasion",
            "TA0006" : "Credential Access",
            "TA0007" : "Discovery",
            "TA0008" : "Lateral Movement",
            "TA0009" : "Collection",
            "TA0011" : "Command and Control",
            "TA0010" : "Exfiltration",
            "TA0040" : "Impact"
        }
    def getPlugInfo(self):
        raise NotImplementedError("This methods needs to provide basic information about the plugin.")
    def getSupportedAttackTactics(self):
        raise NotImplementedError("This methods needs to provide the list of tactics supported by the plugin.")
    def getModulesForTactics(self, techID: str):
        raise NotImplementedError("This method needs to provide all the realted module given the tactic ID of ATT&CK Framework.")
    def fireModule(self, module: str, host: str, port: int):
        raise NotImplementedError("This method will fire the specified module at the given port and either return a session or a failure message.")
    