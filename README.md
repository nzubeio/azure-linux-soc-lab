# Azure Linux SOC Lab

A Linux virtual machine deployed in Microsoft Azure and exposed to the public internet to attract real-world SSH brute force attacks. Logs were forwarded to Microsoft Sentinel for threat detection, analytics rule creation, incident generation, and global attack visualization.

---

## Tools and Technologies

- Microsoft Azure (Resource Group, Virtual Network, Network Security Group, Virtual Machine)
- Ubuntu Server 24.04 LTS
- Azure Monitor Agent
- Log Analytics Workspace
- Microsoft Sentinel
- KQL (Kusto Query Language)

---

## Architecture

1. Linux VM exposed to the internet on port 22 (SSH)
2. Azure Monitor Agent installed on VM to forward Syslog to Log Analytics Workspace
3. Microsoft Sentinel connected to Log Analytics Workspace
4. Custom analytics rule detects SSH brute force attempts
5. Sentinel automatically generates incidents for each detection
6. Attack map workbook visualizes attacker locations globally

---

## Lab Build

### Step 1 - Resource Group
Created a dedicated Resource Group (rg-linux-soc-lab) in East US to logically organize all lab infrastructure.

![Resource Group](screenshots/01-resource-group.png)

### Step 2 - Virtual Network
Created a Virtual Network (vnet-linux-soc-lab) with address space 10.0.0.0/16 to provide isolated network infrastructure for the lab.

![Virtual Network](screenshots/02-virtual-network.png)

### Step 3 - Network Security Group
Created a Network Security Group (nsg-linux-soc-lab) to control inbound and outbound traffic. Configured to allow SSH traffic from the internet so attackers can reach the VM.

![NSG Created](screenshots/03-nsg-created.png)
![NSG Deployed](screenshots/04-nsg-deployed.png)

### Step 4 - Linux Virtual Machine
Deployed an Ubuntu Server 24.04 LTS VM (Standard_D2as_v5) with SSH key authentication and port 22 open to the public internet.

![VM Configuration](screenshots/05-vm-configuration.png)
![VM SSH Config](screenshots/06-vm-ssh-config.png)
![VM Validation](screenshots/07-vm-validation.png)
![VM Deployed](screenshots/08-vm-deployed.png)
![VM Running](screenshots/09-vm-running.png)

### Step 5 - System Update and Log Verification
Connected to the VM via SSH and updated all system packages. Verified that Linux authentication logs were being recorded in /var/log/auth.log. Real attackers were already attempting SSH logins within minutes of deployment.

![Ubuntu Updated](screenshots/10-ubuntu-updated.png)
![Auth Logs](screenshots/11-auth-logs.png)

### Step 6 - Log Analytics Workspace
Created a Log Analytics Workspace (law-linux-soc-lab) as the central log repository. Installed Azure Monitor Agent on the VM to forward Syslog data to the workspace.

![Log Analytics Deployed](screenshots/12-log-analytics-deployed.png)
![Log Analytics Overview](screenshots/13-log-analytics-overview.png)
![VM Extensions Before](screenshots/14-vm-extensions-empty.png)
![Logs Flowing](screenshots/15-logs-flowing.png)

### Step 7 - Microsoft Sentinel
Enabled Microsoft Sentinel on the Log Analytics Workspace. Created a scheduled analytics rule to detect SSH brute force attempts. Sentinel automatically generated incidents for each detection.

![Sentinel Incidents](screenshots/16-sentinel-incidents.png)
![Incident Detail](screenshots/17-incident-detail.png)

### Step 8 - Attack Map
Built a Sentinel Workbook to visualize global attack traffic. The map shows real attackers from multiple countries attempting to brute force the exposed VM.

![Attack Map](screenshots/18-attack-map.png)

---

## Detection Logic

Custom KQL analytics rule used to detect SSH brute force attempts:

```kql
Syslog
| where Facility == "auth"
| where SyslogMessage contains "Failed password"
| extend SourceIP = extract(@"from (\S+) port", 1, SyslogMessage)
| where isnotempty(SourceIP)
| summarize FailedAttempts = count() by SourceIP, bin(TimeGenerated, 1h)
| where FailedAttempts > 5
| sort by FailedAttempts desc
```

---

## Results

| Metric | Count |
|--------|-------|
| Syslog entries collected | 94,800 |
| Security alerts triggered | 452 |
| Incidents auto-generated | 450 |
| Countries attacking | Multiple worldwide |

---

## Lessons Learned

- Exposing a Linux VM to the internet attracts automated SSH brute force attacks within minutes
- Azure Monitor Agent provides reliable log forwarding from Linux VMs to Log Analytics Workspace
- Microsoft Sentinel analytics rules can automatically detect and generate incidents from raw log data
- KQL is a powerful query language for filtering and analyzing security events at scale
- Geographic attack visualization helps identify threat actor origins and attack patterns
