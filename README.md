# Guardian Angel

`Guardian Angel` is a distributed, multi-tier Intrusion Prevention System (IPS) designed to monitor, detect, and dynamically mitigate network attacks targeting a virtual network environment. Built as a collection of decoupled, highly resilient Python microservices, the system performs real-time traffic analysis, cryptographic validation, SQL-backed state persistence, and programmatic firewall orchestration. It was built and tested to be used in defending a Metaploitable 2 VM from a Kali attacker.

## Features

* **Multi-Tier Microservice Architecture**: Decouples sniffing, threat analysis, and firewall orchestration into three separate components (Sensor, Analyzer, and Enforcer) communicating over distinct UDP and TCP channels.
* **Cryptographic Integrity**: Uses HMAC-SHA256 signatures to authenticate messages sent between services, verified using constant-time comparison.
* **State Recovery & Persistence**: Employs an active SQLite transaction database to record active blocks. On restart, it automatically calculates remaining cooldown intervals and schedules background unblocks using non-blocking asynchronous timers.

---

## System Architecture

```text
Network Architecture Map

        ┌─────────────────────────────────────────────────────────────┐
        │                        GATEWAY VM                           │
        │                                                             │
        │   ┌───────────────┐                  ┌──────────────────┐   │
        │   │    Sensor     │                  │    Analyzer      │   │
  Transit   │               │ ────────────────>│                  │   │
  Traffic ─>│  [sensor.py]  │   HMAC-Signed    │  [analyzer.py]   │   │
            └───────────────┘    Telemetry     └────────┬─────────┘   │
                                                        │             │
                                           HMAC-Signed  │             │
                                            JSON Cmd    │             │
                                                        v             │
                                                        │             │
            ┌───────────────┐                  ┌────────┴─────────┐   │
            │   iptables    │<─────────────────│     Enforcer     │   │
            │  (Firewall)   │  Shell execution │                  │   │
            └───────────────┘                  │  [enforcer.py]   │   │
                                               └──────────────────┘   │
        └─────────────────────────────────────────────────────────────┘
```

## Installation

Clone or download this repository to your local machine:
```bash
git clone https://github.com/Snowymonkey/GuardianAngel
cd GuardianAngel
pip3 install scapy
```
To ensure secure communication between microservices, generate a hmac_key:
```bash
python3 generate-key.py
```

## Configuration

```json
{
  "sensor_ip": "127.0.0.1",
  "analyzer_ip": "127.0.0.1",
  "enforcer_ip": "127.0.0.1",
  "analyzer_port": 5005,
  "enforcer_port": 5006,
  "network_interface": "lo0",
  "hmac_key": "REPLACE_ME",
  "syn_threshold": 10,
  "ssh_threshold": 100,
  "block_time": 300
}
```

| Config Value | Description |
|-----------|------------|
| `sensor_ip` | Public IP of the Sensor |
| `analyzer_ip` | Public IP of the Analyzer |
| `enforcer_ip` | Public IP of the Enforcer |
| `analyzer_port` | Port that the Analyzer listens on |
| `enforcer_port` | Port that the Enforcer listens on |
| `network_interface` | The network interface which the Sensor sniffs packets on |
| `hmac_key` | Cryptographic key which is used to generate the signatures the micro services use to verify recieved traffic. It must be the same in all configs. |
| `syn_threshold` | The maximum number of syn packets that can be sniffed in 1 second before a rate limit is activated |
| `ssh_threshold` | The maximum number of ssh packets that can be sniffed in 1 second before a rate limit is activated |
| `block_time` | The time in seconds in which the IP is blocked / rate limited |

For a simple 1 Kali attacker set up, I recommend the `syn_threshold` to be set to 10 and the ssh_`threshold` to be set to 100.

## Usage

To use `Guardian Angel` start the processes in order (sensor.py -> analysis.py -> enforcer.py), and shut them down in reverse order when you are finished using ^C (enforcer.py -> analysis.py -> sensor.py). While `Guardian Angel` has error handling if one or more of the systems fail, firewall rules will not be written as each service depends on one another to properly sniff packets, identify patterns, and execute firewall rules.

| Micro-Service | Description | Requirments |
|-----------|------------|------------|
| `sensor.py` | Sniffs packets and sends parsed telemetry data to `analysis.py` | Requires sudo |
| `analysis.py` | Reads parsed telemtry data from `sensor.py` and identifies suspicious patterns. When thresholds are reached it will send commands to `enforcer.py` | No privileges |
| `enforcer.py` | Writes firewall rules from recieved from `analysis.py` | Requires sudo |


## Defence Details

* **Active Threat Detection**: The analysis engine monitors real-time telemetry to actively identify and mitigate the following behaviors:

* **SYN Port Scanning**: Detects when a host attempts to sweep unique destination ports within a sliding 1-second window.

* **Anomalous Scans**: Instantly catches stealthy, non-standard TCP reconnaissance sequences including Null (0) and Xmas (FPU) flag combinations.

* **SSH Brute-Forcing**: Tracks successive connection attempt frequencies targeting TCP Port 22 to block high-rate credential-guessing.

## Notes

* Video coming soon!!
