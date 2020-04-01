"""
Module handling the complete RESTful API with the help of Database Handler
"""
from flask import Flask, request
from flask_classful import FlaskView, route
from api_utils import APIUtils
from database_handler import DatabaseHandler
from flask_cors import CORS
import socketio
import eventlet
import json

DBHANLDE = DatabaseHandler()
socketIOServer = socketio.Server(cors_allowed_origins='*')


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
        return DBHANLDE.login(username, password), 200


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
        return DBHANLDE.register(firstname, lastname, username, emailaddress, password, companyname), 200


class RecoverView(FlaskView):
    representations = {'application/json': APIUtils.output_json}

    def get(self):
        return {'success': False, 'error': "Method Not Allowed"}, 405

    @route('/generate', methods=['POST'])
    def generate_code(self):
        if 'username' not in request.json:
            return {'success': False, 'error': 'Please provide your username to recover your account.'}
        if not DBHANLDE.username_exists(request.json['username']):
            return {'success': False, 'error': 'Username is not registered.'}
        return DBHANLDE.send_password_recovery(request.json['username'])

    @route('/verify', methods=['POST'])
    def verify_code(self):
        if 'username' not in request.json:
            return {'success': False, 'error': 'Please provide your username to recover your account.'}
        if not DBHANLDE.username_exists(request.json['username']):
            return {'success': False, 'error': 'Username is not registered.'}
        if 'code' not in request.json:
            return {'success': False, 'error': 'Please provide recovery code sent to your email address.'}
        if 'newpassword' not in request.json:
            return {'success': False, 'error': 'Please provide new password to set.'}
        return DBHANLDE.recover_account(request.json['username'], request.json['code'], request.json['newpassword'])


class UserView(FlaskView):
    representations = {'application/json': APIUtils.output_json}

    def post(self):
        if (not FlaskAPI.check_token()) or "username" not in request.json.keys():
            return {"status": False, "error": "You are not logged in to access this resource."}, 403
        return DBHANLDE.get_user_info(request.json['username'])

    @route('/verifyemail', methods=['POST'])
    def verifyemail(self):
        if (not FlaskAPI.check_token()) or "username" not in request.json.keys():
            return {"status": False, "error": "You are not logged in to access this resource."}, 403
        if "code" in request.json.keys():
            try:
                _ = int(request.json['code'])
                return DBHANLDE.verify_email_address(request.json['username'], int(request.json['code']))
            except:
                return {"status": False, "error": "Verification Code must only consist of numbers."}
        return {"status": False, "error": "Please provide verification code."}

    @route('/changepublicip', methods=['POST'])
    def changepublicip(self):
        if (not FlaskAPI.check_token()) or "username" not in request.json.keys():
            return {"status": False, "error": "You are not logged in to access this resource."}, 403
        if "ip" in request.json.keys():
            return DBHANLDE.change_agent_ip(request.json['username'], request.json['ip'])
        return {"status": False, "error": "Please provide Public IP Address of agent."}

    @route('/changepassword', methods=['POST'])
    def change_password(self):
        if (not FlaskAPI.check_token()) or "username" not in request.json.keys():
            return {"status": False, "error": "You are not logged in to access this resource."}, 403
        new_password = request.json.get("newpassword", "")
        if new_password == "":
            return {'status': False, "error": "Password cannot be empty."}
        return DBHANLDE.change_password(request.json['username'], new_password)

    # @route('/verifypublicip', methods=['POST'])
    # def verifypublicip(self):
    #     if (not FlaskAPI.check_token()) or "username" not in request.json.keys():
    #         return {"status": False, "error": "You are not logged in to access this resource."}, 403
    #     return DBHANLDE.verify_public_ip(request.json['username'])


class AgentView(FlaskView):
    def before_request(self, name):
        FlaskAPI.check_token()

    @route('/addlocalsystem', methods=['POST'])
    def addlocalsystem(self):
        if "username" not in request.json.keys():
            return {'success': False, 'error': "You are no logged in to access this resource."}
        if 'localip' not in request.json:
            return {'success': False, 'error': "Please provide a valid Local IP."}
        return DBHANLDE.add_local_system(request.json['username'], request.json['localip'])

    @route('/deletelocalsystem', methods=['POST'])
    def deletelocalsystem(self):
        if "username" not in request.json.keys():
            return {'success': False, 'error': "You are not logged in to access this resource."}
        if 'localip' not in request.json:
            return {'success': False, 'error': "Please provide a valid Local IP."}
        return DBHANLDE.remove_local_system(request.json['username'], request.json['localip'])

    @route('/changelocalsystemip', methods=['POST'])
    def changelocalsystemip(self):
        if "username" not in request.json.keys():
            return {'success': False, 'error': "You are not logged in to access this resource."}
        if 'oldlocalip' not in request.json:
            return {'success': False, 'error': "Please provide a valid old Local IP."}
        if 'newlocalip' not in request.json:
            return {'success': False, 'error': "Please provide a valid new Local IP."}
        return DBHANLDE.change_local_system_ip(request.json['username'], request.json['oldlocalip'], request.json['newlocalip'])

    @route('/logs', methods=['POST'])
    def get_all_logs(self):
        if "username" not in request.json.keys():
            return {'success': False, 'error': "You are not logged in to access this resource."}
        return DBHANLDE.get_scanning_events_by_username(request.json['username'])

    def post(self):
        if "username" not in request.json.keys():
            return {'success': False, 'error': "You are not logged in to access this resource."}
        return DBHANLDE.get_local_systems(request.json['username'])

    @route('/getsystemstatus', methods=['POST'])
    def get_current_status(self):
        if "username" not in request.json.keys():
            return {'success': False, 'error': "You are not logged in to access this resource."}
        if 'localip' not in request.json:
            return {'success': False, 'error': "Please provide a valid Local IP."}
        return DBHANLDE.get_local_system_status(request.json['username'], request.json['localip'])

    @route('/exploitlogs', methods=['POST'])
    def get_exploitation_logs(self):
        if "username" not in request.json.keys():
            return {'success': False, 'error': "You are not logged in to access this resource."}
        if not "localip" in request.json:
            return {'success': False, 'error': "Please provide IP of Local System."}
        return DBHANLDE.get_exploitation_data(request.json['username'], request.json['localip'])

    @route('/latestexploitlogs', methods=['POST'])
    def get_latest_exploitation_logs(self):
        if "username" not in request.json.keys():
            return {'success': False, 'error': "You are not logged in to access this resource."}
        if not "localip" in request.json:
            return {'success': False, 'error': "Please provide IP of Local System."}
        return DBHANLDE.get_latest_exploitation_data(request.json['username'], request.json['localip'])


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
    #     data = DBHANLDE.get_agent_ip(username)
    #     if not data['success']:
    #         request.json['ipverified'] = False
    #         return False
    #     if request.remote_addr == data['ip'] and data['ipverified']:
    #         request.json['ipverified'] = True
    #         return True
    #     request.json['ipverified'] = False
    #     return False


if __name__ == '__main__':

    connected_clients = {}

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
            socketIOServer.emit('connection_failed', json.dumps({'reason':'Invalid Token!'}), to=sid)
            socketIOServer.disconnect(sid)
        response = DBHANLDE.change_agent_ip(auth_data['username'], environ['REMOTE_ADDR'])
        if(response['success'] == False):
            socketIOServer.emit('connection_failed', json.dumps({'reason': response['error']}), to=sid)
        connected_clients[str(sid)] = {'agent_ip': environ['REMOTE_ADDR'], 'username': auth_data['username']}

        


    @socketIOServer.event
    def message(sid, data):
        
        print('message ', data)
        socketIOServer.disconnect(sid)

    @socketIOServer.event
    def disconnect(sid):
        if str(sid) in connected_clients:
            client = connected_clients[str(sid)]
            DBHANLDE.change_agent_ip(client['username'], None)
            print(client['username'] + "(" + client['agent_ip'] + ")" + " disconnected")

    FlaskAPP = FlaskAPI()
    CORS(FlaskAPP)
    APP = socketio.WSGIApp(socketIOServer, FlaskAPP)
    # APP.wsgi_app.run(host="0.0.0.0", port=8080, debug=True)
    eventlet.wsgi.server(eventlet.listen(('', 8080)), APP)
