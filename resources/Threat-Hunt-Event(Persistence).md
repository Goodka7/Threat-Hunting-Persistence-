# Threat Event (Persistence & Backdoor Access)

**Unauthorized Persistence Mechanisms & Backdoor Creation**

## Steps the "Bad Actor" took to Create Logs and IoCs:

1. **Deployed a persistent backdoor by adding a malicious systemd service.**
   - The attacker created and executed a malicious systemd service (`malicious.service`) to maintain persistence. Logs showed the execution of the service creation and its subsequent activation to run on system startup.

2. **Created a Trojanized script that mimics a common administrative command to maintain access.**
   - The attacker created a Trojanized `ls` command at `/home/baddog/.local/bin/ls` to execute a reverse shell. Execution of the Trojanized command was detected, indicating the attacker's attempt to maintain ongoing access.

3. **Created a SUID backdoor shell (`/tmp/rootbash`) to escalate privileges to root.**
   - The attacker created a backdoor shell (`/tmp/rootbash`), modified its ownership, and set the SUID permission to escalate privileges. This was executed to gain root access on the system.

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
**Notes**
