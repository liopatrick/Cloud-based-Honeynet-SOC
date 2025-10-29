
# Azure Honeynet & SOC

## Architecture and Overview

This mini honeynet was built in Azure to ingest logs from various resources into a Log Analytics Workspace, which is then used by Microsoft Sentinel to build attack maps, trigger alerts, and create incidents. Security metrics in the insecure environment were measured for 24 hours. Security controls were applied to harden the environment. Metrics were measured for another 24 hours, and then results were recorded. The metrics collected are:

- SecurityEvent (Windows Event Logs)
- Syslog (Linux Event Logs)
- SecurityAlert (Log Analytics Alerts Triggered)
- SecurityIncident (Incidents created by Sentinel)
- AzureNetworkAnalytics_CL (Malicious Flows allowed into the honeynet)

The architecture of the mini honeynet in Azure consists of the following components:

- Virtual Network (VNet)
- Network Security Group (NSG)
- Virtual Machines (2 windows, 1 linux)
- Log Analytics Workspace
- Azure Key Vault
- Azure Storage Account
- Microsoft Sentinel


## Attack Maps Before Hardening / Security Controls
<img width="735" alt="Capture1" src="https://github.com/kphillip1/azure-soc-honeynet/assets/165929885/6201e7a7-6e1e-4759-bca5-c820e125190c">
<br><br>
<img width="593" alt="Capture2" src="https://github.com/kphillip1/azure-soc-honeynet/assets/165929885/ccefa380-5948-4dd6-b52c-f303648fb68e">
<br><br>
<img width="598" alt="Capture3" src="https://github.com/kphillip1/azure-soc-honeynet/assets/165929885/3406fac0-c152-4684-bc3a-236ff35a9eb4">
<br><br>

## Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in the insecure environment for 24 hours:
<br>
| Start Time 2025-09-13 13:53:48
<br>
| Stop Time 2025-09-14 13:53:48

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 7671
| Syslog                   | 833
| SecurityAlert            | 4
| SecurityIncident         | 59
| AzureNetworkAnalytics_CL | 620

## Attack Maps After Hardening / Security Controls

<img width="231" alt="noresults" src="https://github.com/kphillip1/azure-soc-honeynet/assets/165929885/031e52cf-266f-40de-a1b1-d8ff313aa746">
<br><br>

```All map queries actually returned no results due to no instances of malicious activity for the 24 hour period after hardening.```

## Metrics After Hardening / Security Controls

The following table shows the metrics we measured in the environment for another 24 hours, but after the applied security controls:
<br>
| Start Time 2024-09-15 11:50:28
<br>
| Stop Time 2024-09-16 11:50:28

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 3894
| Syslog                   | 6
| SecurityAlert            | 0
| SecurityIncident         | 0
| AzureNetworkAnalytics_CL | 0

![image](https://github.com/kphillip1/azure-soc-honeynet/assets/165929885/3d5a9f41-fd9f-4e0c-bfa1-85da4b249939)


Microsoft Sentinel was employed to trigger alerts and create incidents based on the ingested logs. The number of security events and incidents were drastically reduced after the security controls were applied, demonstrating their effectiveness.


## KQL Queries

| Metric                                       | Query                                                                                                                                            |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| Start/Stop Time                              | range x from 1 to 1 step 1<br>\| project StartTime = ago(24h), StopTime = now()                                                                  |
| Security Events (Windows VMs)                | SecurityEvent<br>\| where TimeGenerated>= ago(24h)<br>\| count                                                                                   |
| Syslog (Linux VMs)                           | Syslog<br>\| where TimeGenerated >= ago(24h)<br>\| count                                                                                         |
| SecurityAlert (Microsoft Defender for Cloud) | Security Alert<br>\| where DisplayName !startswith "CUSTOM" and DisplayName !startswith "TEST"<br>\| where TimeGenerated >= ago(24h)<br>\| count |
| Security Incident (Sentinel Incidents)       | SecurityIncident<br>\| where TimeGenerated >= ago(24h)<br>\| count                                                                               |
| NSG Inbound Malicious Flows Allowed          | AzureNetworkAnalytics_CL<br>\| where FlowType_s == "MaliciousFlow" and AllowedInFlows_d > 0<br>\| where TimeGenerated >= ago(24h)<br>\| count    |
