import psutil
import argparse
import logging
import time
import os
import json

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


MALICIOUS_IPS = load_malicious_ips()

def setup_argparse():
    """Sets up the argument parser."""
    parser = argparse.ArgumentParser(description="Network Connection Analyzer for a specific process.")
    parser.add_argument("-p", "--pid", type=int, required=True, help="Process ID to monitor.")
    parser.add_argument("-d", "--duration", type=int, default=10, help="Duration (in seconds) to capture network connections. Default is 10 seconds.")
    parser.add_argument("-o", "--output", type=str, help="Output file to save the connection data (JSON format).")
    parser.add_argument("-u", "--update-blocklist", action="store_true", help="Update malicious IP blocklist from a remote source (not implemented).")
    parser.add_argument("-l", "--log-level", type=str, default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Set the logging level.")
    return parser.parse_args()


def analyze_connections(pid, duration):
    """Captures and analyzes network connections for a given PID."""
    try:
        process = psutil.Process(pid)
    except psutil.NoSuchProcess:
        logging.error(f"Process with PID {pid} not found.")
        return []
    except psutil.AccessDenied:
        logging.error(f"Access denied when trying to access process with PID {pid}.  Run with elevated privileges.")
        return []
    except Exception as e:
        logging.error(f"An unexpected error occurred while accessing process with PID {pid}: {e}")
        return []

    logging.info(f"Monitoring network connections for PID {pid} for {duration} seconds...")
    start_time = time.time()
    connections = []

    while time.time() - start_time < duration:
        try:
            new_connections = process.connections(kind='inet')
            for conn in new_connections:
                connection_details = {
                    "local_address": conn.laddr.address,
                    "local_port": conn.laddr.port,
                    "remote_address": conn.raddr.address if conn.raddr else None,
                    "remote_port": conn.raddr.port if conn.raddr else None,
                    "protocol": conn.type,  # socket.SOCK_STREAM (TCP) or socket.SOCK_DGRAM (UDP)
                    "status": conn.status, # TCP state (e.g., ESTABLISHED, TIME_WAIT)
                    "is_malicious": conn.raddr.address in MALICIOUS_IPS if conn.raddr else False
                }
                connections.append(connection_details)
        except psutil.NoSuchProcess:
             logging.error(f"Process with PID {pid} no longer exists.")
             return connections
        except psutil.AccessDenied:
            logging.warning(f"Access denied while retrieving connections for PID {pid}.  Run with elevated privileges or investigate.")
            # Non-fatal, continue monitoring.  Could be intermittent.
        except Exception as e:
            logging.error(f"An error occurred while retrieving connections for PID {pid}: {e}")

        time.sleep(1) # Check connections every 1 second

    logging.info(f"Finished monitoring PID {pid}.")
    return connections

def save_to_json(data, output_file):
    """Saves the connection data to a JSON file."""
    try:
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=4)
        logging.info(f"Connection data saved to {output_file}")
    except Exception as e:
        logging.error(f"Error saving data to {output_file}: {e}")

def main():
    """Main function to execute the network connection analyzer."""
    args = setup_argparse()

    # Set logging level
    logging.getLogger().setLevel(args.log_level.upper())

    pid = args.pid
    duration = args.duration
    output_file = args.output

    if pid <= 0:
        logging.error("PID must be a positive integer.")
        return

    if duration <= 0:
        logging.error("Duration must be a positive integer.")
        return

    # Input validation complete, continue execution
    logging.debug(f"Starting analysis with PID: {pid}, Duration: {duration}, Output file: {output_file}")

    connections = analyze_connections(pid, duration)

    if connections:
        logging.info(f"Found {len(connections)} network connections.")

        # Print connections and flag malicious ones
        for conn in connections:
            log_message = f"Connection: Local {conn['local_address']}:{conn['local_port']}, Remote {conn['remote_address']}:{conn['remote_port']}, Protocol: {conn['protocol']}, Status: {conn['status']}"
            if conn['is_malicious']:
                log_message += " - **MALICIOUS IP DETECTED!**"
                logging.warning(log_message)  # Log malicious connections as warnings
            else:
                logging.info(log_message)

        if output_file:
            save_to_json(connections, output_file)
    else:
        logging.info("No network connections found or an error occurred.")

if __name__ == "__main__":
    main()