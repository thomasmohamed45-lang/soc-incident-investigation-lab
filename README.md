# SOC Incident Investigation & SIEM Detection Lab

## Overview

This project demonstrates a hands-on Security Operations Center (SOC) workflow using Splunk Enterprise to collect Windows security telemetry, investigate failed authentication activity, develop an SPL detection rule, and configure automated alerting.

The lab was built in an isolated VirtualBox environment using an Ubuntu Server running Splunk Enterprise and a Windows endpoint running the Splunk Universal Forwarder.

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

The Windows endpoint was configured to forward the following event logs to Splunk:

- Security
- System
- Application

Splunk successfully received Windows Security telemetry from the endpoint through the Universal Forwarder.

## Incident Simulation

A temporary lab account named `SOC-TestUser` was created.

Multiple controlled authentication attempts were performed using an incorrect password to generate Windows Security Event ID `4625` events.

This simulated repeated failed authentication activity in a safe lab environment.

## Investigation

Splunk was used to investigate the failed authentication events.

The investigation identified:

- EventCode: `4625`
- Account: `SOC-TestUser`
- Logon Type: `3` (Network)
- Failure Reason: Unknown user name or bad password
- Status: `0xC000006D`
- Sub Status: `0xC000006A`
- Source Network Address: `127.0.0.1`

The failed attempts occurred within seconds of one another, providing the activity necessary to test a repeated-failed-logon detection.

![Failed Logon Investigation](screenshots/Screenshot%20%28488%29.png)

## Detection Engineering

An SPL detection was developed to identify accounts generating five or more failed Windows logons within a five-minute window.

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
| bin _time span=5m
| stats count as Failed_Logins by _time Account_Name Source_Network_Address
| where Failed_Logins >= 5 AND NOT match(Account_Name, "\$$")
| sort - Failed_Logins
