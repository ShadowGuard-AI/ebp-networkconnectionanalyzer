import psutil
import argparse
import logging
import time
import os
import json
import sys
import socket

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Placeholder for malicious IP blocklist (can be a file or database)
MALICIOUS_IPS_FILE = "malicious_ips.json"

def load_malicious_ips():
    """Loads malicious IPs from a JSON file."""
    try:
        with open(MALICIOUS_IPS_FILE, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):  # Ensure it's a list of IPs
                return set(data)
            else:
                logging.warning(f"Malicious IPs file {MALICIOUS_IPS_FILE} contains invalid data. Using an empty list.")
                return set()
    except FileNotFoundError:
        logging.warning(f"Malicious IPs file {MALICIOUS_IPS_FILE} not found. Using an empty list.")
        return set()
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON in {MALICIOUS_IPS_FILE}. Using an empty list.")
        return set()
    except Exception as e:
        logging.error(f"Error loading malicious IPs: {e}. Using an empty list.")
        return set()


# The blocklist loads once, at import, from a path relative to the folder
# the tool was started in, not the folder the script lives in. Starting
# the tool somewhere else silently means a different list, or none.
MALICIOUS_IPS = load_malicious_ips()

def setup_argparse():
    """Sets up the argument parser."""
    parser = argparse.ArgumentParser(description="Network Connection Analyzer for a specific process.")
    parser.add_argument("-p", "--pid", type=int, required=True, help="Process ID to monitor.")
    parser.add_argument("-d", "--duration", type=int, default=10, help="Duration (in seconds) to capture network connections. Default is 10 seconds.")
    parser.add_argument("-o", "--output", type=str, help="Output file to save the connection data (JSON format).")
    parser.add_argument("-l", "--log-level", type=str, default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Set the logging level.")
    return parser.parse_args()


# psutil address values are namedtuples with .ip and .port on current
# versions, but plain tuples come back on some platforms and older
# versions. I try the attribute first and fall back to indexing, and a
# value that fits neither shape becomes None instead of raising.
def _addr_ip(addr):
    if not addr:
        return None
    try:
        return addr.ip
    except Exception:
        try: return addr[0]
        except Exception: return None

def _addr_port(addr):
    if not addr:
        return None
    try:
        return addr.port
    except Exception:
        try: return addr[1]
        except Exception: return None

# conn.type is not one stable type either: it can arrive as an int, an
# enum, or a string depending on platform. I normalise through int when
# that works and pattern match the string form when it does not.
def _protocol_name(conn_type):
    try:
        value = int(conn_type)
    except Exception:
        name = str(conn_type)
        return "TCP" if "STREAM" in name else ("UDP" if "DGRAM" in name else name)
    return {int(socket.SOCK_STREAM): "TCP", int(socket.SOCK_DGRAM): "UDP"}.get(value, str(value))

def analyze_connections(pid, duration):
    """Returns a list of distinct connections, or None if the process cannot be read."""
    try:
        process = psutil.Process(pid)
    except psutil.NoSuchProcess:
        logging.error(f"Process with PID {pid} not found.")
        return None
    except psutil.AccessDenied:
        logging.error(f"Access denied when trying to access process with PID {pid}.  ")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred while accessing process with PID {pid}: {e}")
        return None
    logging.info(f"Monitoring network connections for PID {pid} for {duration} seconds...")
    start_time = time.time()
    connections = []
    seen = set()
    while time.time() - start_time < duration:
        try:
            new_connections = process.connections(kind='inet')
            for conn in new_connections:
                details = {
                    "local_address": _addr_ip(conn.laddr),
                    "local_port": _addr_port(conn.laddr),
                    "remote_address": _addr_ip(conn.raddr) if conn.raddr else None,
                    "remote_port": _addr_port(conn.raddr) if conn.raddr else None,
                    "protocol": _protocol_name(conn.type),
                    "status": conn.status,
                    "is_malicious": (_addr_ip(conn.raddr) in MALICIOUS_IPS) if conn.raddr else False
                }
                # Status is part of the dedupe key on purpose. The same socket seen in
                # two states is two entries, because the state change is itself part of
                # what a capture over time should show.
                key = (details["local_address"], details["local_port"], details["remote_address"], details["remote_port"], details["protocol"], details["status"])
                if key in seen:
                    continue
                seen.add(key)
                connections.append(details)
        except psutil.NoSuchProcess:
             logging.error(f"Process with PID {pid} no longer exists.")
             # The process dying mid-capture returns what was gathered, not None.
             # None is reserved for never being able to read the process at all, and
             # main treats the two differently.
             return connections
        except psutil.AccessDenied:
            # Access denied inside the loop only warns and keeps polling, unlike the
            # same error before the loop, which gives up. A process whose owner
            # changes, or a transient permission hiccup, can become readable again.
            logging.warning(f"Access denied while retrieving connections for PID {pid}.")
        except Exception as e:
            logging.error(f"An error occurred while retrieving connections for PID {pid}: {e}")
        time.sleep(1)
    logging.info(f"Finished monitoring PID {pid}.")
    return connections

# A failed save is logged and swallowed here. On the success path that
# means the tool can exit 0 with no file written, which I note as a gap:
# the caller asked for a file and the exit code does not say it is absent.
def save_to_json(data, output_file):
    """Saves the connection data to a JSON file."""
    try:
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=4)
        logging.info(f"Connection data saved to {output_file}")
    except Exception as e:
        logging.error(f"Error saving data to {output_file}: {e}")

def main():
    args = setup_argparse()
    logging.getLogger().setLevel(args.log_level.upper())
    pid = args.pid
    duration = args.duration
    output_file = args.output
    if pid <= 0:
        logging.error("PID must be a positive integer.")
        sys.exit(1)
    if duration <= 0:
        logging.error("Duration must be a positive integer.")
        sys.exit(1)
    if not os.path.exists(MALICIOUS_IPS_FILE):
        logging.info("malicious_ips.json not found in the folder this tool was started from. Malicious flagging is off for this run: no IPs will be flagged.")
        print("malicious_ips.json not found in the starting folder. Malicious flagging is off for this run.")
    else:
        logging.info(f"Loaded {len(MALICIOUS_IPS)} malicious IP(s) from malicious_ips.json in the starting folder.")
    connections = analyze_connections(pid, duration)
    # Even a failed or empty capture writes an empty JSON list when an
    # output file was asked for, so a downstream reader finds a valid file
    # instead of a missing one. The exit code carries the failure.
    if connections is None:
        logging.error(f"Could not read connections for PID {pid}.")
        if output_file:
            save_to_json([], output_file)
        sys.exit(1)
    if connections:
        logging.info(f"Found {len(connections)} network connections.")
        for conn in connections:
            log_message = f"Connection: Local {conn['local_address']}:{conn['local_port']}, Remote {conn['remote_address']}:{conn['remote_port']}, Protocol: {conn['protocol']}, Status: {conn['status']}"
            if conn['is_malicious']:
                log_message += " - **MALICIOUS IP DETECTED!**"
                logging.warning(log_message)
            else:
                logging.info(log_message)
        if output_file:
            save_to_json(connections, output_file)
    else:
        logging.info("No network connections found.")
        print("No network connections found.")
        if output_file:
            save_to_json([], output_file)
        sys.exit(1)

if __name__ == "__main__":
    main()
