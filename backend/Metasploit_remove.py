from util import Utilty
import configparser
import os
import sys
from Msgrpc import Msgrpc
from __const import *
import time
import codecs
from bs4 import BeautifulSoup
import json

# Metasploit's environment.
class Metasploit:
    def __init__(self, target_ip='127.0.0.1'):
        self.util = Utilty()
        self.rhost = target_ip
        # Read config.ini.
        full_path = os.path.dirname(os.path.abspath(__file__))
        config = configparser.ConfigParser()
        try:
            config.read(os.path.join(full_path, 'config.ini'))
        except FileExistsError as err:
            self.util.print_message(FAIL, 'File exists error: {}'.format(err))
            sys.exit(1)
        # Common setting value.
        server_host = config['Common']['server_host']
        server_port = int(config['Common']['server_port'])
        self.msgrpc_user = config['Common']['msgrpc_user']
        self.msgrpc_pass = config['Common']['msgrpc_pass']
        self.timeout = int(config['Common']['timeout'])
        self.max_attempt = int(config['Common']['max_attempt'])
        self.save_path = os.path.join(full_path, config['Common']['save_path'])
        self.save_file = os.path.join(self.save_path, config['Common']['save_file'])
        self.data_path = os.path.join(full_path, config['Common']['data_path'])
        if os.path.exists(self.data_path) is False:
            os.mkdir(self.data_path)
        self.plot_file = os.path.join(self.data_path, config['Common']['plot_file'])
        self.port_div_symbol = config['Common']['port_div']

        # Metasploit options setting value.
        self.lhost = server_host
        self.lport = int(config['Metasploit']['lport'])
        self.proxy_host = config['Metasploit']['proxy_host']
        self.proxy_port = int(config['Metasploit']['proxy_port'])
        self.prohibited_list = str(config['Metasploit']['prohibited_list']).split('@')
        self.path_collection = str(config['Metasploit']['path_collection']).split('@')

        # Nmap options setting value.
        self.nmap_command = config['Nmap']['command']
        self.nmap_timeout = config['Nmap']['timeout']
        self.nmap_2nd_command = config['Nmap']['second_command']
        self.nmap_2nd_timeout = config['Nmap']['second_timeout']

        # A3C setting value.
        self.train_worker_num = int(config['A3C']['train_worker_num'])
        self.train_max_num = int(config['A3C']['train_max_num'])
        self.train_max_steps = int(config['A3C']['train_max_steps'])
        self.train_tmax = int(config['A3C']['train_tmax'])
        self.test_worker_num = int(config['A3C']['test_worker_num'])
        self.greedy_rate = float(config['A3C']['greedy_rate'])
        self.eps_steps = int(self.train_max_num * self.greedy_rate)

        # State setting value.
        self.state = []                                            # Deep Exploit's state(s).
        self.os_type = str(config['State']['os_type']).split('@')  # OS type.
        self.os_real = len(self.os_type) - 1
        self.service_list = str(config['State']['services']).split('@')  # Product name.

        # Report setting value.
        self.report_test_path = os.path.join(full_path, config['Report']['report_test'])
        self.report_train_path = os.path.join(self.report_test_path, config['Report']['report_train'])
        # if os.path.exists(self.report_train_path) is False:
        #     os.mkdir(self.report_train_path)
        self.scan_start_time = self.util.get_current_date()
        self.source_host= server_host

        self.client = Msgrpc({'host': server_host, 'port': server_port})  # Create Msgrpc instance.
        self.client.login(self.msgrpc_user, self.msgrpc_pass)  # Log in to RPC Server.
        self.client.get_console()                              # Get MSFconsole ID.
        self.buffer_seq = 0
        self.isPostExploit = False  
       # Execute Nmap.
    def execute_nmap(self, rhost, command, timeout):
        self.util.print_message(NOTE, 'Execute Nmap against {}'.format(rhost))
        if os.path.exists(os.path.join(self.data_path, 'target_info_' + rhost + '.json')) is False:
            # Execute Nmap.
            self.util.print_message(OK, '{}'.format(command))
            self.util.print_message(OK, 'Start time: {}'.format(self.util.get_current_date()))
            _ = self.client.call('console.write', [self.client.console_id, command])

            time.sleep(3.0)
            time_count = 0
            while True:
                # Judgement of Nmap finishing.
                ret = self.client.call('console.read', [self.client.console_id])
                try:
                    if (time_count % 5) == 0:
                        self.util.print_message(OK, 'Port scanning: {} [Elapsed time: {} s]'.format(rhost, time_count))
                        self.client.keep_alive()
                    if timeout == time_count:
                        self.client.termination(self.client.console_id)
                        self.util.print_message(OK, 'Timeout   : {}'.format(command))
                        self.util.print_message(OK, 'End time  : {}'.format(self.util.get_current_date()))
                        break

                    status = ret.get(b'busy')
                    if status is False:
                        self.util.print_message(OK, 'End time  : {}'.format(self.util.get_current_date()))
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
        else:
            self.util.print_message(OK, 'Nmap already scanned.')

    # Get port list from Nmap's XML result.
    def get_port_list(self, nmap_result_file, rhost):
        self.util.print_message(NOTE, 'Get port list from {}.'.format(nmap_result_file))
        global com_port_list
        port_list = []
        proto_list = []
        info_list = []
        if os.path.exists(os.path.join(self.data_path, 'target_info_' + rhost + '.json')) is False:
            nmap_result = ''
            # cat_cmd = 'cat ' + nmap_result_file + '\n'
            # _ = self.client.call('console.write', [self.client.console_id, cat_cmd])
            # time.sleep(3.0)
            # time_count = 0
            # while True:
            #     # Judgement of 'services' command finishing.
            #     ret = self.client.call('console.read', [self.client.console_id])
            #     try:
            #         if self.timeout == time_count:
            #             self.client.termination(self.client.console_id)
            #             self.util.print_message(OK, 'Timeout: "{}"'.format(cat_cmd))
            #             break

            #         nmap_result += ret.get(b'data').decode('utf-8')
            #         status = ret.get(b'busy')
            #         if status is False:
            #             break
            #     except Exception as e:
            #         self.util.print_exception(e, 'Failed: console.read')
            #     time.sleep(1.0)
            #     time_count += 1

            with open(nmap_result_file) as f:
                nmap_result = f.read()
                

            # Get port, protocol, information from XML file.
            port_list = []
            proto_list = []
            info_list = []
            bs = BeautifulSoup(nmap_result, 'lxml')
            ports = bs.find_all('port')
            for idx, port in enumerate(ports):
                port_list.append(str(port.attrs['portid']))
                proto_list.append(port.attrs['protocol'])

                for obj_child in port.contents:
                    if obj_child.name == 'service':
                        temp_info = ''
                        if 'product' in obj_child.attrs:
                            temp_info += obj_child.attrs['product'] + ' '
                        if 'version' in obj_child.attrs:
                            temp_info += obj_child.attrs['version'] + ' '
                        if 'extrainfo' in obj_child.attrs:
                            temp_info += obj_child.attrs['extrainfo']
                        if temp_info != '':
                            info_list.append(temp_info)
                        else:
                            info_list.append('unknown')
                # Display getting port information.
                self.util.print_message(OK, 'Getting {}/{} info: {}'.format(str(port.attrs['portid']),
                                                                            port.attrs['protocol'],
                                                                            info_list[idx]))

            if len(port_list) == 0:
                self.util.print_message(WARNING, 'No open port.')
                self.util.print_message(WARNING, 'Shutdown Deep Exploit...')
                self.client.termination(self.client.console_id)
                exit(1)

            # Update com_port_list.
            com_port_list = port_list

            # Get OS name from XML file.
            some_os = bs.find_all('osmatch')
            os_name = 'unknown'
            for obj_os in some_os:
                for obj_child in obj_os.contents:
                    if obj_child.name == 'osclass' and 'osfamily' in obj_child.attrs:
                        os_name = (obj_child.attrs['osfamily']).lower()
                        break

            # Set OS to state.
            for (idx, os_type) in enumerate(self.os_type):
                if os_name in os_type:
                    self.os_real = idx
        else:
            # Get target host information from local file.
            saved_file = os.path.join(self.data_path, 'target_info_' + rhost + '.json')
            self.util.print_message(OK, 'Loaded target tree from : {}'.format(saved_file))
            fin = codecs.open(saved_file, 'r', 'utf-8')
            target_tree = json.loads(fin.read().replace('\0', ''))
            fin.close()
            key_list = list(target_tree.keys())
            for key in key_list[2:]:
                port_list.append(str(key))

            # Update com_port_list.
            com_port_list = port_list

        return port_list, proto_list, info_list
