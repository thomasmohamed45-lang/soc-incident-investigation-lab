# SOC Incident Investigation & SIEM Detection Lab

## Overview

This project demonstrates a hands-on Security Operations Center (SOC) workflow using Splunk Enterprise to collect Windows security telemetry, investigate failed authentication activity, develop an SPL detection rule, and configure automated alerting.

The lab was built using an Ubuntu Server running Splunk Enterprise and a Windows endpoint running the Splunk Universal Forwarder.

## Lab Architecture

Windows Endpoint  
↓  
Splunk Universal Forwarder  
↓ TCP 9997  
Ubuntu Splunk Enterprise Server  
↓  
Windows Security Event Analysis  
↓  
SPL Detection & Alerting

## Technologies Used

- Splunk Enterprise
- Splunk Universal Forwarder
- Windows Security Event Logs
- Ubuntu Server
- VirtualBox
- PowerShell
- SSH
- SPL (Search Processing Language)

## Data Collection

The Windows endpoint was configured to forward Security, System, and Application event logs to Splunk.

Splunk successfully received Windows Security telemetry through the Universal Forwarder.

## Incident Simulation

A temporary lab account named `SOC-TestUser` was created.

Multiple controlled authentication attempts were performed using an incorrect password to generate Windows Security Event ID `4625` events.

This simulated repeated failed authentication activity in an authorized lab environment.

## Investigation

Splunk analysis identified:

- EventCode: `4625`
- Account: `SOC-TestUser`
- Logon Type: `3` (Network)
- Failure Reason: Unknown user name or bad password
- Status: `0xC000006D`
- Sub Status: `0xC000006A`
- Source Network Address: `127.0.0.1`

The failed attempts occurred within seconds of one another, providing the activity necessary to test a repeated-failed-logon detection.

![Failed Logon Detection](screenshots/Screenshot%20%28488%29.png)

## Detection Engineering

An SPL detection was developed to identify accounts generating five or more failed Windows logons within a five-minute window.

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
| bin _time span=5m
| stats count as Failed_Logins by _time Account_Name Source_Network_Address
| where Failed_Logins >= 5 AND NOT match(Account_Name, "\$$")
| sort - Failed_Logins
```

The detection successfully identified `SOC-TestUser` after six failed authentication attempts.

## Automated Alerting

The detection was converted into a scheduled Splunk alert named **Repeated Failed Logon Detection**.

Configuration:

- Schedule: Every 5 minutes
- Search window: Last 5 minutes
- Trigger condition: Number of results greater than 0
- Severity: Medium
- Action: Add to Triggered Alerts

![Alert Configuration](screenshots/Screenshot%20%28494%29.png)

## Detection Validation

Additional controlled failed authentication attempts were generated after the alert was enabled.

Splunk successfully triggered the alert, validating the detection from endpoint activity through automated SIEM alerting.

![Triggered Alert](screenshots/Screenshot%20%28501%29.png)

## Event Investigation

The underlying Event ID 4625 records were reviewed to validate the account, logon type, failure reason, status codes, source address, workstation, and timing.

![Event 4625 Investigation](screenshots/Screenshot%20%28503%29.png)

## Response and Remediation

After validating the detection and completing the investigation, the temporary `SOC-TestUser` account was removed from the Windows endpoint.

## Skills Demonstrated

- SIEM deployment and configuration
- Windows Security Event Log analysis
- Splunk Universal Forwarder configuration
- Log ingestion and monitoring
- SPL query development
- Detection engineering
- Windows Event ID 4625 investigation
- Authentication analysis
- Alert creation and validation
- False-positive filtering
- Incident investigation
- Linux server administration
- SSH administration
- Virtual networking
- Security documentation

## Conclusion

This lab demonstrates an end-to-end SOC detection workflow rather than simply installing a SIEM.

Windows security telemetry was collected and forwarded to Splunk, suspicious authentication activity was generated in a controlled environment, Event ID 4625 events were investigated, an SPL detection was developed, and a scheduled alert was successfully triggered and validated.

The project demonstrates practical experience moving from raw endpoint telemetry to detection, investigation, alerting, and response.

## Disclaimer

All authentication activity was intentionally generated in an authorized home lab environment for educational and portfolio purposes.
