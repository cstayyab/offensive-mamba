import os
import json

class QLAI:
    def __init__(self, tblfile="tbl.json"):
        self.locked = True
        self.tbl = []
        data_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data")
        self.tblfile = os.path.join(data_dir, tblfile)
        if os.path.isfile(self.tblfile):
            with open(self.tblfile, "r") as t:
                self.tbl = json.load(t)
        
    def get_actions(self, os, product, version, port):
        self._get_lock()
        for row in self.tbl:
            state = row['state']
            _os = state['os']
            _product = state['product']
            _version = state['version']
            _port = state['port']
            if _os == os and _product == product and _version == version and _port == port:
                self.locked = False
                return row['actions']
        self.locked = False
        return None
    def get_reward(self, os, product, version, port, engine, exploit, payload):
        actions = self.get_actions(os, product, version, port)
        self._get_lock()
        if actions is None:
            self.locked = False
            return 0
        else:
            for action in actions:
                _engine = action[0]['engine']
                _exploit = action[0]['exploit']
                _payload = action[0]['payload']
                if engine == _engine and exploit == _exploit and payload == _payload:
                    reward = action[1]
                    return reward
    
    def _get_lock(self):
        while self.locked:
            continue
        self.locked = True

    def step(self, os, product, version, port, engine, exploit, payload):
        prev_reward = self.get_reward(os, product, version, port, engine, exploit, payload)
        if prev_reward == -1:
            return False
        else:
            return True

        
    def set_reward(self, os, product, version, port, engine, exploit, payload, reward):
        actions = self.getActions(os, product, version, port)
        self._get_lock()
        if actions in None:
            _state = {
                'os': os,
                'product': product,
                'version': version,
                'port': port
            }
            _actions = []
            _actions.append(({
                "_engine": engine,
                "_exploit": exploit,
                "_payload": payload
            }, reward))
            self.tbl.append({'state': _state, 'actions': _actions})
        else:
            for i in range(len(self.tbl)):
                _state = self.tbl[i]['state']
                _os = _state['os']
                _product = _state['product']
                _version = _state['version']
                _port = _state['port']
                _actions = self.tbl[i]['actions']
                for j in range(len(_actions)):
                    _engine = _actions[j][0]['engine']
                    _exploit = _actions[j][0]['exploit']
                    _payload = _actions[j][0]['payload']
                    if _os == os and _product == product and _version == version and _port == port and _engine == engine and _exploit == exploit and _payload == payload:
                        self.tbl[i]['actions'][j][1] = reward
                        self.locked = False
                        return
        self.locked = False
    
    def save_file(self):
        self._get_lock()
        with open(self.tblfile, "w") as f:
            json.dump(f)
        self.locked = False

        