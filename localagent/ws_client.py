import socketio
import requests
import json
from getpass import getpass
from system_scan import SystemScan
import msgpack
import time
import os
import configparser
from util import Utility
from __const import *
import http.client
from netifaces import interfaces, ifaddresses, AF_INET
import traceback
import requests
BASE_URL = "http://115.186.176.141:8080"
HEADERS = {'Content-Type': 'application/json'}

sio = socketio.Client()




def ip4_addresses():
    ip_list = []
    for interface in interfaces():
        if AF_INET in ifaddresses(interface):
            for link in ifaddresses(interface)[AF_INET]:
                ip_list.append(link['addr'])
    return ip_list


def service_get_agentip(req):
    all_ips = ip4_addresses()
    target_ip = req['ip']
    matches = [0,0,0,0]
    agent_ip = ""
    for i, ip in enumerate(all_ips):
        split_ip = str(ip).split(".")
        split_target_ip = str(target_ip).split(".")
        if split_ip == split_target_ip:
            matches[i]  = 4
        elif split_ip[:-1] == split_target_ip[:-1]:
            matches[i] = 3
        elif split_ip[:-2] == split_target_ip[:-2]:
            matches[i] = 2
        elif split_ip[:-3] == split_target_ip[:-3]:
            matches[i] = 1
        else:
            matches[i] = 0
    if max(matches) > 0:
        agent_ip = all_ips[matches.index(max(matches))]
        response = {
            'request_id': req['request_id'],
            'service': 'agent_ip',
            'success': True,
            'agent_ip': agent_ip
        }
        sio.emit('response', data=response)
    else:
        response = {
            'request_id': req['request_id'],
            'service': 'agent_ip',
            'success': False,
            'reason': 'No relevant interface'
        }
        sio.emit('response', data=response)


def service_nmap(req):
    scanner = SystemScan(req['ip'])
    scanner.start_scan()
    scandata = scanner.xml
    scanfile = scanner.get_xml_in_file()
    response = {
        "request_id": req['request_id'],
        "service": "nmap",
        "scandata": scandata,
        "localfile": scanfile
    }
    sio.emit("response", data=response) # Not Thread safe
    sio.sleep(0)


def decode_array(arr):
    pass

# Send HTTP request.
def msgrpc_service(req):
    util = Utility()
    # Read config.ini.
    full_path = os.path.dirname(os.path.abspath(__file__))
    config = configparser.ConfigParser()
    try:
        config.read(os.path.join(full_path, 'config.ini'))
    except FileExistsError as err:
        util.print_message(FAIL, 'File exists error: {}'.format(err))
        response = {
            "request_id": req['request_id'],
            "service": "msgrpc",
            "success": False,
            "reason": "Config File not found!"
        }
        sio.emit("response", data=json.dumps(response))    
        return
    meth = req['method']
    if meth == 'auth.login':
        req['option'] = ['auth.login', str(config['Common']['msgrpc_user']), str(config['Common']['msgrpc_pass'])]
    options_meta = req['option']
    uri = req['uri']
    # origin_option = req['origin_option']
    headers = req['headers']
    if meth != 'auth.login':
        option = []
        for op in options_meta:
            if op['type'] == "bytes":
                option.append(bytes(op['value'], "utf-8"))
            else:
                option.append(op['value'])
    else:
        option = req['option']
    params = msgpack.packb(option)
    resp = ''
    
    
    host = "172.18.0.1"
    port = int(config['Common']['server_port'])
    # client = http.client.HTTPSConnection(host, port)
    try:
        # client.request("POST", uri, params, headers)
        # resp = client.getresponse()
        resp = requests.post("http://" + host + ":" + str(port) +uri, data=params, headers=headers)
        open('response.bin', "wb").write(resp.content)
        sio.emit("response", data={"request_id": req['request_id'],"service": "msgrpc",'success': True, 'data': resp.content})
        return
        res = msgpack.unpackb(resp.content, strict_map_key=False, raw=False)
        print("Response: " + str(res))
        decoded_res = []
        for key, value in res.items():
            op = []
            if type(key).__name__ == "bytes":
                op.append({'type': type(key).__name__, 'value': key.decode('utf-8')})
            else:
                op.append({'type': type(key).__name__, 'value': key})
            if type(value).__name__ == "bytes":
                op.append({'type': type(value).__name__, 'value': value.decode('utf-8')})
            else:
                op.append({'type': type(value).__name__, 'value': value})
            decoded_res.append(op)
        print("\n\nDecoded: ", str(decoded_res))
        response = {
            "request_id": req['request_id'],
            "service": "msgrpc",
            "success": True,
            "resp": decoded_res
        }
        sio.emit("response", data=response)
    except Exception as err:
        traceback.print_exc()
        response = {
            "request_id": req['request_id'],
            "service": "msgrpc",
            "success": False,
            "reason": "auth"
        }
        sio.emit("response", data=response) 

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
    if req['service'] == "nmap":
        service_nmap(req)
    elif req['service'] == "msgrpc":
        msgrpc_service(req)
    elif req['service'] == "agent_ip":
        service_get_agentip(req)


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

print('Trying to connect . . . ', )
sio.connect(BASE_URL, headers={"Authorization": "Bearer " + token})
sio.wait()
