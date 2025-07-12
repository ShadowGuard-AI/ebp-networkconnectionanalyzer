# ebp-NetworkConnectionAnalyzer
A simple command-line utility that captures and analyzes network connections established by a specific process (identified by PID) over a short duration, reporting on destination IPs, ports, and protocols, and flagging connections to known malicious IPs (using a locally updated blocklist). - Focused on Analyzes and profiles typical endpoint (computer, server) behavior based on resource consumption (CPU, memory, disk I/O), process activity, and network connections. Detects anomalies suggesting malware or unauthorized activity.  Collects baselines and alerts on deviations. WMI dependency is optional; the tool can function with reduced capabilities on non-Windows platforms using only psutil.

## Install
`git clone https://github.com/ShadowGuardAI/ebp-networkconnectionanalyzer`

## Usage
`./ebp-networkconnectionanalyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-p`: Process ID to monitor.
- `-d`: No description provided
- `-o`: No description provided
- `-u`: No description provided
- `-l`: Set the logging level.

## License
Copyright (c) ShadowGuardAI
