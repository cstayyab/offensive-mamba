import threading
from MetasploitCannon import MetasploitCannon
from database_handler import DatabaseHandler
from system_scan import SystemScan


DBHANDLE = DatabaseHandler()

def scan_all_systems(username: str):
    systems: list = DBHANDLE.get_local_systems(username).get("data", None)
    print("{} : All Systems: {}".format(username, str(systems)))

    if (systems is None) or len(systems) == 0:
        return
    agent_ip = DBHANDLE.get_agent_ip(username).get("ip", None)
    if agent_ip is None:
        return
    password = DBHANDLE.get_password(username)
    for system in systems:
        print("Scanning " + system + "...")
        scanner = SystemScan(system)
        scanner.start_scan()
        MetasploitCannon(agent_ip, system, username, password, scanner.get_xml_in_file()).run()

def scan_all_users():
    while True:
        user_threads = []
        usernames = DBHANDLE.get_all_usernames()
        for username in usernames:
            job = lambda username=username: scan_all_systems(username)
            user_thread = threading.Thread(daemon=False, target=job)
            user_thread.name = "mainthread_" + username
            user_threads.append(user_thread)
            user_thread.start()
        while True:
            alive_count = 0
            for user_thread in user_threads:
                if user_thread.is_alive():
                    alive_count += 1
            if alive_count == 0:
                break

if __name__ == "__main__":
    scan_all_users()