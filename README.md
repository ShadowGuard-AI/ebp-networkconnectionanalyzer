![Banner](banner.png)

# ebp-NetworkConnectionAnalyzer
A simple command-line utility that captures and analyzes network connections established by a specific process (identified by PID) over a short duration, reporting on destination IPs, ports, and protocols, and flagging connections to known malicious IPs. Malicious flagging needs an operator supplied malicious_ips.json file in the folder the tool is started from; the repo ships no such file, and a run logs a plain line when that file is absent and flagging is off. - Focused on Analyzes and profiles typical endpoint (computer, server) behavior based on resource consumption (CPU, memory, disk I/O), process activity, and network connections. Detects anomalies suggesting malware or unauthorized activity.  Collects baselines and alerts on deviations. WMI dependency is optional; the tool can function with reduced capabilities on non-Windows platforms using only psutil.

## Install
`git clone https://github.com/ShadowGuardAI/ebp-networkconnectionanalyzer`

## Usage
`python3 main.py -p PID [-d seconds] [-o output.json]`

Notes on behaviour:
- Each distinct connection is counted once per run, however many sampling seconds it is seen in. Protocol is reported as a name, TCP or UDP.
- Malicious flagging needs an operator supplied malicious_ips.json in the folder the tool is started from. When that file is absent, the run logs a plain line saying flagging is off.
- If no connections are found, the run logs a plain line and exits 1. If -o was requested, the output file is still written, holding an empty list, so a requested file never silently does not exist.
- An unusable PID (for example a bad PID or 0) or a duration of 0 exits 1 with the reason logged.
- There is no --update-blocklist flag; it was a dead flag and has been removed.

## Parameters
- `-h`: Show help message and exit
- `-p`: Process ID to monitor.
- `-d`: No description provided
- `-o`: No description provided
- `-l`: Set the logging level.

## License
Copyright (c) ShadowGuardAI
