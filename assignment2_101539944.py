"""
Author: Ishan Sood
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

# Print Python version and operating system name
print("Python Version:", platform.python_version())
print("Operating System:", os.name)

# Maps common port numbers to their associated network service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}


class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property and @target.setter lets us control how the target attribute is
    # read and written without exposing the private __target directly. The setter can
    # validate the value before storing it, preventing invalid data from ever entering
    # the object. This is safer and more maintainable than allowing direct attribute access.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits from NetworkTool, so it automatically gets the target property,
# its getter and setter validation logic, and the destructor — without rewriting any of
# that code. For example, calling super().__init__(target) in PortScanner's constructor
# stores the target using NetworkTool's private attribute and validation logic.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        # Q4: What would happen without try-except here?
        # Without try-except, any socket error (e.g. connection refused, timeout, or
        # network unreachable) would raise an unhandled exception and crash the entire
        # program — including all running threads. With try-except, we catch socket.error
        # gracefully and allow the scanner to continue checking remaining ports uninterrupted.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            status = "Open" if result == 0 else "Closed"
            service_name = common_ports.get(port, "Unknown")
            with self.lock:
                self.scan_results.append((port, status, service_name))
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Each port scan waits up to 1 second for a response, so scanning 1024 ports
    # sequentially could take over 17 minutes in the worst case. Threading lets us
    # scan many ports simultaneously, reducing total scan time to just a few seconds.
    # Without threads, the program would block on each port before moving to the next.
    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)

        for t in threads:
            t.start()

        for t in threads:
            t.join()


def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )""")
        for result in results:
            port, status, service = result
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, port, status, service, str(datetime.datetime.now()))
            )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")


def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()
        if not rows:
            print("No past scans found.")
        else:
            for row in rows:
                _, target, port, status, service, scan_date = row
                print(f"[{scan_date}] {target} : Port {port} ({service}) - {status}")
        conn.close()
    except sqlite3.Error:
        print("No past scans found.")


# ── Main Program ──

target = input("Enter target IP address (press Enter for 127.0.0.1): ").strip()
if target == "":
    target = "127.0.0.1"

try:
    start_port = int(input("Enter start port (1-1024): ").strip())
    if not (1 <= start_port <= 1024):
        print("Port must be between 1 and 1024.")
        exit()
except ValueError:
    print("Invalid input. Please enter a valid integer.")
    exit()

try:
    end_port = int(input("Enter end port (1-1024): ").strip())
    if not (1 <= end_port <= 1024):
        print("Port must be between 1 and 1024.")
        exit()
    if end_port < start_port:
        print("End port must be greater than or equal to start port.")
        exit()
except ValueError:
    print("Invalid input. Please enter a valid integer.")
    exit()

scanner = PortScanner(target)
print(f"\nScanning {target} from port {start_port} to {end_port}...")
scanner.scan_range(start_port, end_port)

open_ports = scanner.get_open_ports()
print(f"\n--- Scan Results for {target} ---")
for port, status, service in open_ports:
    print(f"Port {port}: Open ({service})")
print("------")
print(f"Total open ports found: {len(open_ports)}")

save_results(target, scanner.scan_results)

show_history = input("\nWould you like to see past scan history? (yes/no): ").strip().lower()
if show_history == "yes":
    load_past_scans()

# Q5: New Feature Proposal
# I would add a port filtering feature that lets the user choose to display only
# ports matching a specific service category (e.g. only "web" ports like HTTP and HTTPS).
# It would use a list comprehension with a nested if-statement to filter scan_results
# by checking both the status ("Open") and whether the service name is in a user-defined
# category list, like: [r for r in results if r[1] == "Open" if r[2] in web_services].
# Diagram: See diagram_101539944.png in the repository root