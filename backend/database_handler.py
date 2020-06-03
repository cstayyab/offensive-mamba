"""
Module that is responsible for all the operation directly liked to database
"""
import time
import random
from uuid import uuid4
from mongoengine import connect
from api_utils import APIUtils
from models import User, LocalSystem, ScanningEvent, ExploitingEvent
import json
validate = APIUtils.validate
from datetime import datetime


class DatabaseHandler:
    """
    Class to handle all calls to Database for the Flask API and the extreme-backend(core)

    """

    def __init__(self, host: str = 'localhost', port: int = 27017, username=None, password=None):
        """Connect to MongoDB and save instances of MongoClient and MongoDatabase"""
        if username is None and password is None:
            connect(db='omamba', host=host, port=port)
        else:
            connect(db='omamba', host=host, port=port, username=username,
                    password=password, authentication_source="admin")

    def local_login(self, username: str, password: str, ipaddr: str) -> dict:
        pass

    def login(self, username: str, password: str) -> dict:
        errors = {}
        if username == "":
            errors['username'] = "Username cannot be empty."
        if password == "":
            errors['password'] = "Password cannot be empty."
        if errors != {}:
            return {'success': False, 'errors': errors}
        elif not self.username_exists(username):
            errors['username'] = "Username is not registered."
            return {'success': False, 'errors': errors}
        else:
            # "Warning"? Issue in pylint: https://github.com/MongoEngine/mongoengine/issues/858
            users = User.objects(
                username=username)
            
            if users.count() == 1 and APIUtils.decrypt_password(users[0].password) == password:

                # Generate JWT Token
                jwt_iat = int(time.time())
                jwt_exp = int(jwt_iat + (60*60*14))  # Expires after 24 hrs
                decrypted_token = {
                    'email': users[0].emailAddress,
                    'username': users[0].username,
                    'publicip': users[0].publicIP,
                    'iat': jwt_iat,
                    'exp': jwt_exp
                }
                return {'success': True, 'emailVerified': users[0].emailVerified, 'message': "Login successful!", 'token': APIUtils.encrypt_jwt_token(decrypted_token)}
            else:
                return {'success': False, 'message': "Invalid username or password!"}

    def get_agent_ip(self, username: str) -> dict:
        if(self.username_exists(username) is False):
            return {"success": False, "error": "Username does not exist!"}
        else:
            # "Warning"? Issue in pylint: https://github.com/MongoEngine/mongoengine/issues/858
            user: User = User.objects(username=username)[0]
            return {"success": True, "ip": user.publicIP, "ipverified": user.verifiedPublicIP}

    def register(self, firstname: str, lastname: str, username: str, emailaddress: str, password: str, companyname: str) -> dict:
        errors = {}

        # Validate all arguments

        # First Name
        if firstname == "":
            errors['firstname'] = "First name cannot be empty"
        elif not validate("firstname", firstname):
            errors['firstname'] = "First name contains invalid characters and/or it should be more than 2 and less then 20 characters long."

        # Last Name
        if lastname == "":
            errors['lastname'] = "Last name cannot be empty"
        elif not validate("lastname", lastname):
            errors['lastname'] = "Last name contains invalid characters and/or it should be more than 2 and less then 20 characters long."

        # password
        if password == "":
            errors['password'] = "Password cannot be empty."
        elif not validate("password", password):
            errors['password'] = "Password must contain 8 or more character with at least 1 lowercase, uppercase, numeric and special symbol character each."

        # Username
        if username == "":
            errors['username'] = "Username cannot be empty."
        elif not validate("username", username):
            errors[
                'username'] = "Username must be 4 to 32 characters long and can only contain alphabets, underscore(_) and period(.)"
        elif self.username_exists(username):
            errors['username'] = "Username already exists."

        # Email
        if emailaddress == "":
            errors['emailaddress'] = "Email Address cannot be empty."
        elif not validate("email", emailaddress):
            errors['emailaddress'] = "Please provide a valid email address."
        elif self.emailaddress_exists(emailaddress):
            errors['emailaddress'] = "Email Address already registered."

        # Comapny Name
        if companyname == "":
            errors['companyname'] = "Compnay name cannot be empty."
        elif not validate("companyname", companyname):
            errors['companyname'] = "Company name contains invalid characters and/or it should be more than 2 and less then 64 characters long."
        # if there are errors return
        if errors != {}:
            return {'success': False, 'errors': errors}

        # All validation tests passed now create a user in database
        user = User(firstName=firstname, lastName=lastname, companyName=companyname,
                    password=APIUtils.encrypt_password(password), username=username,
                    emailAddress=emailaddress, emailVerified=False
                    )
        user.save()
        # TODO check for error returned by generateRecoveryCode
        self.generateRecoveryCode(user, "verifyEmail")
        # return with successful message
        return {'success': True, 'message': "Your account has successfully been created"}

    def change_password(self, username: str, new_password: str) -> dict:
        if not self.username_exists(username):
            return {'success': False, 'message': 'Invalid Username!'}
        user: User = User.objects(username=username)[0]
        if not validate("password", new_password):
            return {'success': False, 'error': "Password must contain 8 or more character with at least 1 lowercase, uppercase, numeric and special symbol character each."}
        user.password = APIUtils.encrypt_password(new_password)
        user.save()
        return {'success': True, 'message': 'Password updated successfully!'}
    
    def send_password_recovery(self, username: str) -> dict:
        # TODO Send Password Recovery
        if not self.username_exists(username):
            return {'success': False, 'error': 'Invalid Username!'}
        user: User = User.objects(username=username)[0]
        self.generateRecoveryCode(user, "resetPassword") # TODO Check for error returned 
        return {'success': True, 'message': "Password Recovery Code emailed."}
    
    def recover_account(self, username: str, recovery_code: int, new_password: str):
        users = User.objects(username=username)
        if users.count() == 0:
            return {"success": False, "error": "Username does not exist."}
        elif validate("password", new_password):
            return {"success": False, "error": "Password does not meet the given criteria"}
        else:
            user: User = users[0]
            if user.codeFor is not None and user.recoveryCode is not None and user.recoveryCode == recovery_code and user.codeFor == "resetPassword":
                user.codeFor = None
                user.recoveryCode = None
                user.password = APIUtils.encrypt_password(new_password)
                user.save()
                return {"success": True, "message": "Password changed Successfully!"}
            return {"success": False, "error": "Invalid Code!"}

    def username_exists(self, username: str) -> bool:
        # "Warning"? Issue in pylint: https://github.com/MongoEngine/mongoengine/issues/858
        return User.objects(username=username).count() > 0
    
    def get_all_usernames(self) -> list:
        users = User.objects()
        usernames = []
        for user in users:
            usernames.append(user.username)
        return usernames

    def emailaddress_exists(self, email: str) -> bool:
        # "Warning"? Issue in pylint: https://github.com/MongoEngine/mongoengine/issues/858
        return User.objects(emailAddress=email).count() > 0

    def generateRecoveryCode(self, user: User, code_for: str) -> bool:
        if code_for not in APIUtils.valid_code_for_choices:
            raise ValueError("Invalid value for CodeFor argument. Must be one of {}".format(
                str(APIUtils.valid_code_for_choices)))
        else:
            # TODO Add a check for error so False can be returned for error
            code = random.randint(100000, 999999)
            user.recoveryCode = code
            user.codeFor = code_for
            user.save()
            # TODO Send Recovery email to user
            return True

    def get_user_info(self, username: str) -> dict:
        # "Warning"? Issue in pylint: https://github.com/MongoEngine/mongoengine/issues/858
        users = User.objects(username=username)
        if users.count() == 0:
            return {"success": False, "error": "Username does not exist."}
        user: User = users[0]
        data = {
            "firstname": user.firstName,
            "lastname": user.lastName,
            "companyName": user.companyName,
            "username": user.username,
            "emailAddress": user.emailAddress,
            "publicIP": user.publicIP,
            "emailVerified": user.emailVerified,
            "verifiedPublicIP": user.verifiedPublicIP
        }
        return {"success": True, "data": data}

    def verify_email_address(self, username: str, code: int) -> dict:
        # "Warning"? Issue in pylint: https://github.com/MongoEngine/mongoengine/issues/858
        users = User.objects(username=username)
        if users.count() == 0:
            return {"success": False, "error": "Username does not exist."}
        else:
            user: User = users[0]
            if (user.codeFor is not None) and (user.recoveryCode is not None) and (user.recoveryCode == code) and (user.codeFor == "verifyEmail"):
                user.emailVerified = True
                user.codeFor = None
                user.recoveryCode = None
                user.save()
                return {"success": True, "message": "Email Verified Successfully!"}
            return {"success": False, "error": "Invalid Code!"}

    def change_agent_ip(self, username: str, ipaddr: str) -> dict:
        if not self.username_exists(username):
            return {"success": False, "error": "Username does not exist!"}
        if (ipaddr is not None) and not APIUtils.validate("ipaddress", ipaddr):
            return {"success": False, "error": "IP Address is invalid! Please provide a valid IPv4 Address."}
        # "Warning"? Issue in pylint: https://github.com/MongoEngine/mongoengine/issues/858
        user: User = User.objects(username=username)[0]
        user.publicIP = ipaddr
        ipverify = str(uuid4())
        user.publicIPVerifier = ipverify
        user.verifiedPublicIP = True
        user.save()
        return {
            "success": True,
            "message": "Please verify IP Ownership by creating a file named the given code in root of web server of that IP Address.",
            "code": ipverify}

    def verify_public_ip(self, username: str) -> dict:
        # TODO access web server and verify the Ip Verifier File
        if not self.username_exists(username):
            return {"success": False, "error": "Username does not exist!"}
        # "Warning"? Issue in pylint: https://github.com/MongoEngine/mongoengine/issues/858
        user: User = User.objects(username=username)[0]
        user.verifiedPublicIP = True
        user.save()
        return {"success": True, "message": "Agent Public IP verfified successfully!"}

    def add_local_system(self, username: str, local_ip: str) -> dict:
        if not self.username_exists(username):
            return {'success': False, 'error': "You are not logged in to access this resource."}
        if not APIUtils.validate('ipaddress', local_ip):
            return {'success': False, 'error': "Please provide a valid IP Address."}

        # "Warning"? Issue in pylint: https://github.com/MongoEngine/mongoengine/issues/858
        user = User.objects(username=username)[0]
        localexists = LocalSystem.objects(
            userId=user, localIP=local_ip).count() > 0
        if localexists:
            return {
                'success': False,
                'error': "A system with this IP is already added to your IP Pool."
                }
        localsys = LocalSystem()
        localsys.userId = user
        localsys.localIP = local_ip
        localsys.os = "Unknown"
        localsys.openPorts = {}
        localsys.systemUp = False
        localsys.save()

        return {'success': True, 'message': "Local System added successfully!"}

    def remove_local_system(self, username: str, local_ip: str) -> dict:
        if not self.username_exists(username):
            return {'success': False, 'error': "You are not logged in to access this resource."}
        if not APIUtils.validate('ipaddress', local_ip):
            return {'success': False, 'error': "Please provide a valid IP Address."}

        # "Warning"? Issue in pylint: https://github.com/MongoEngine/mongoengine/issues/858
        user = User.objects(username=username)[0]
        localexists = LocalSystem.objects(
            userId=user, localIP=local_ip).count() > 0
        if not localexists:
            return {
                'success': False,
                'error': "A system with this IP does not exists in your IP Pool."
            }
        localsys: LocalSystem = LocalSystem.objects(
            userId=user, localIP=local_ip)
        localsys.delete()
        return {'success': True, 'message': "Local System deleted successfully!"}

    def change_local_system_ip(self, username: str, old_local_ip: str, new_local_ip: str) -> dict:
        if not self.username_exists(username):
            return {'success': False, 'error': "You are not logged in to access this resource."}
        if not APIUtils.validate('ipaddress', old_local_ip):
            return {'success': False, 'error': "Please provide a valid old Local IP Address."}
        if not APIUtils.validate('ipaddress', new_local_ip):
            return {'success': False, 'error': "Please provide a valid new Local IP Address."}

        # "Warning"? Issue in pylint: https://github.com/MongoEngine/mongoengine/issues/858
        user = User.objects(username=username)[0]
        oldlocalexists = LocalSystem.objects(
            userId=user, localIP=old_local_ip).count() > 0
        newlocalexists = LocalSystem.objects(
            userId=user, localIP=new_local_ip).count() > 0
        if not oldlocalexists:
            return {
                'success': False,
                'error': "A system with this IP does not exists in your IP Pool."
                }
        if newlocalexists:
            return {
                'success': False,
                'error': "A system with this IP is already exists in your IP Pool."
                }
        localsys: LocalSystem = LocalSystem.objects(
            userId=user, localIP=old_local_ip)[0]
        localsys.localIP = new_local_ip
        localsys.save()
        return {'success': True, 'message': "Local System's IP changed successfully!"}

    def get_password(self, username: str) -> str:
        user: User = User.objects(username=username)[0]
        return APIUtils.decrypt_password(user.password)
    
    def get_local_systems(self, username: str) -> str:

        if not self.username_exists(username):
            return {'success': False, 'error': "You are not logged in to access this resource."}

        # "Warning"? Issue in pylint: https://github.com/MongoEngine/mongoengine/issues/858
        user: User = User.objects(username=username)[0]
        localsystems = LocalSystem.objects(userId=user)
        systems = []
        for lsys in localsystems:
            systems.append(lsys.localIP)
        return {'success': True, 'count': localsystems.count(), 'data': systems}
    
    def get_local_system_status(self, username: str, localip: str):
        if not self.username_exists(username):
            return {'success': False, 'error': 'Invalid Username!'}
        if not validate('ipaddress', localip):
            return {'success': False, 'error': 'Invalid IPv4 Address!'}
        user: User = User.objects(username=username)[0]
        localsys: list = LocalSystem.objects(userId=user, localIP=localip)
        if localsys.count() == 0:
            return {'success': False, 'error': 'This IPv4 does not exists in you IPv4 Pool.'}
        lsystem: LocalSystem = localsys[0]
        if (lsystem.closedPorts is None):
            lsystem.closedPorts = []
        data = {
            "openPorts": lsystem.openPorts,
            "closedPorts": lsystem.closedPorts,
            "os": lsystem.os,
            "up": lsystem.systemUp,
            "lastScanTime": lsystem.lastScanTime
        }
        return {'success': True, 'data': data}
        


    def insert_scanning_log(self, openports: dict, username: str, localip: str, os: str, closed_ports: list) -> dict:
        if not self.username_exists(username):
            return {'success': False, 'error': 'Invalid Username!'}
        if not validate('ipaddress', localip):
            return {'success': False, 'error': 'Invalid IPv4 Address!'}
        user: User = User.objects(username=username)[0]
        localsys: list = LocalSystem.objects(userId=user, localIP=localip)
        if localsys.count() == 0:
            return {'success': False, 'error': 'This IPv4 does not exists in you IPv4 Pool.'}
        lsystem: LocalSystem = localsys[0]
        is_up = len(list(openports.items())) > 0
        lsystem.systemUp = is_up
        lsystem.os = os
        lsystem.openPorts = openports
        lsystem.closedPorts = closed_ports
        lsystem.save()
        event = ScanningEvent(systemId=lsystem, openPorts=openports, systemUp=is_up, closedPorts=closed_ports)
        event.save()
        event.reload()
        lsystem.lastScanTime = event.scanTime
        lsystem.save()
        return {'success': True, 'message': "Scanning Event Logged!!", 'event': event}

    def get_scanning_events_by_username(self, username: str) -> str:
        if not self.username_exists(username):
            return {'success': False, 'error': 'Invalid Username!'}
        user: User = User.objects(username=username)[0]
        localsys: list = LocalSystem.objects(userId=user)
        data = {}
        for lsystem in localsys:
            events_list = ScanningEvent.objects(systemId=lsystem)
            events = []
            for event in events_list:
                event_data = {"scanTime": event.scanTime, "systemUp": event.systemUp, "openPorts": event.openPorts}
                events.append(event_data)
            data[lsystem['localIP']] = events
        return {'success': True, 'data': data}

    # def insert_scanning_log_by_ip(self, publicip: str, localip: str, openports: dict, os: str, closed_ports: list):
    #     users = User.objects(publicIP=publicip)
    #     if users.count() == 0:
    #         return {'success': False, 'error': "The Agent IP is not registered to any user."}
    #     return self.insert_scanning_log(openports, users[0].username, localip, os, closed_ports)
    
    # def insert_exploitation_log_by_ip(self, publicip: str, localip: str, exploit: str, payload: str, using: str, port: int, success: bool, scanningevent: ScanningEvent):
    #     users = User.objects(publicIP=publicip)
    #     if users.count() == 0:
    #         return {'success': False, 'error': "The Agent IP is not registered to any user."}
    #     return self.insert_exploitation_log(users[0].username, localip, exploit, payload, using, port, success, scanningevent)

    def insert_exploitation_log(self, username: str, localip: str, exploit: str, payload: str, using: str, port: int, success: bool, scanningevent: ScanningEvent) -> dict:
        if not self.username_exists(username):
            return {'success': False, 'error': 'Invalid Username!'}
        if not validate('ipaddress', localip):
            return {'success': False, 'error': 'Invalid IPv4 Address!'}
        user: User = User.objects(username=username)[0]
        localsys: list = LocalSystem.objects(userId=user, localIP=localip)
        if localsys.count() == 0:
            return {'success': False, 'error': 'This IPv4 does not exists in you IPv4 Pool.'}
        lsystem: LocalSystem = localsys[0]
        # portdata = lsystem.openPorts[str(port)]
        # print(scanningevent)
        # scanningevent = ScanningEvent(**scanningevent)
        event = ExploitingEvent(systemId=lsystem, exploitedUsing=using, exploit=exploit, payload=payload, success=success, port=port, scanId=scanningevent) #  vulnName=vulnname, vulnDescription=vulndescription, sessionType=sessiontype
        event.save()
        return {'success': True, 'message': "Exploitation Event Logged!!", 'event': event}
    
    def get_exploitation_data(self, username: str, localip: str) -> dict:
        if not self.username_exists(username):
            return {'success': False, 'error': 'Invalid Username!'}
        if not validate('ipaddress', localip):
            return {'success': False, 'error': 'Invalid IPv4 Address!'}
        user: User = User.objects(username=username)[0]
        localsys: list = LocalSystem.objects(userId=user, localIP=localip)
        if localsys.count() == 0:
            return {'success': False, 'error': 'This IPv4 does not exists in you IPv4 Pool.'}
        lsystem: LocalSystem = localsys[0]
        events = ExploitingEvent.objects(systemId=lsystem)
        events_data = []
        for event in events:
            event_data = {}
            event_data['exploit'] = event['exploit']
            event_data['payload'] = event['payload']
            event_data['port'] = event['port']
            event_data['using'] = event.exploitedUsing
            event_data['timestamp'] = event.timestamp
            events_data.append(event_data)
        return {'success': True, 'data': events_data, 'count': len(events_data)}

    def get_latest_exploitation_data(self, username: str, localip: str) -> dict:
        if not self.username_exists(username):
            return {'success': False, 'error': 'Invalid Username!'}
        if not validate('ipaddress', localip):
            return {'success': False, 'error': 'Invalid IPv4 Address!'}
        user: User = User.objects(username=username)[0]
        localsys: list = LocalSystem.objects(userId=user, localIP=localip)
        if localsys.count() == 0:
            return {'success': False, 'error': 'This IPv4 does not exists in you IPv4 Pool.'}
        lsystem: LocalSystem = localsys[0]
        if lsystem.lastScanTime is None:
            return {'success': True, 'data': {}}
        scanevents: list = ScanningEvent.objects(systemId=lsystem, scanTime=lsystem.lastScanTime)
        if scanevents.count() == 0:
            lsystem.lastScanTime = None
            lsystem.save()
            return {'success': True, 'data': {}}
        scanevent = scanevents[0]
        exploit_events: list = ExploitingEvent.objects(systemId=lsystem, scanId=scanevent)
        events_data = []
        for event in exploit_events:
            event_data = {}
            event_data['exploit'] = event.exploit
            event_data['payload'] = event.payload
            event_data['port'] = event.port
            event_data['using'] = event.exploitedUsing
            event_data['timestamp'] = event.timestamp
            events_data.append(event_data)
        return {'success': True, 'data': events_data}

    # TODO DO POST EXPLOITATION
