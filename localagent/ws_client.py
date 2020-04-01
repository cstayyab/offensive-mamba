import socketio
import requests
import json
from getpass import getpass

BASE_URL = "http://115.186.176.141:8080"
HEADERS = {'Content-Type': 'application/json'}

sio = socketio.Client()

@sio.event
def connect():
    print("[SUCCESS]")

@sio.event
def message(data):
    print(data)

@sio.event
def connection_failed(data):
    print("[FAILED]")

@sio.event
def disconnect():
    print('Disconnected from server')
    exit(0)

@sio.event
def request(data):
    req = json.loads(data)
    print(req)
    
token = ""
while True:
    username = input("Enter Username: ")
    password = getpass("Enter Password: ")
    credentials = {"username": username, "password": password}
    resp = requests.post(BASE_URL + "/login/", data=json.dumps(credentials), headers=HEADERS)
    response = resp.json()
    if(response['success']):
        token = response['token']
        break
    print(response['message'])

print('Trying to connect . . . ', )
sio.connect(BASE_URL, headers={"Authorization": "Bearer " + token})
sio.wait()