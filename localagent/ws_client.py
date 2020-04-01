import socketio
import requests

sio = socketio.Client()

@sio.event
def connect():
    print('Connection established with Offensive Mamba Server')

@sio.event
def message(data):
    print('message received with ', data)
    sio.emit('message', {'response': 'my response'})

@sio.event
def disconnect():
    print('disconnected from server')



sio.connect('http://115.186.176.141:8080', headers={})
sio.wait()