# Threat Event (Persistence & Backdoor Access)

**Unauthorized Persistence Mechanisms & Backdoor Creation**

## Steps the "Bad Actor" took to Create Logs and IoCs:

1. Created a rogue SSH key for persistent access by modifying `~/.ssh/authorized_keys`.
2. Deployed a persistent backdoor by adding a malicious systemd service.
3. Created a Trojanized script that mimics a common administrative command to maintain access.
4. Created a SUID backdoor shell (`/tmp/rootbash`) to escalate privileges to root.

---

## Tables Used to Detect IoCs:

| **Parameter** | **Description** |
|--------------|----------------|
| **Name** | DeviceProcessEvents |
| **Info** | [DeviceProcessEvents Table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| **Purpose** | Used to detect unauthorized execution of backdoor shells, Trojanized commands, and privilege escalation attempts. |

| **Parameter** | **Description** |
|--------------|----------------|
| **Name** | DeviceFileEvents |
| **Info** | [DeviceFileEvents Table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) |
| **Purpose** | Used to detect modifications to `~/.ssh/authorized_keys`, systemd service files, and creation of SUID backdoor binaries. |

| **Parameter** | **Description** |
|--------------|----------------|
| **Name** | DeviceLogonEvents |
| **Info** | [DeviceLogonEvents Table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table) |
| **Purpose** | Used to detect unauthorized remote logins or unusual authentication patterns. |

---

## Related Queries:

```kql
// Detect unauthorized SSH key additions
DeviceFileEvents
| where FileName == "~/.ssh/authorized_keys"
| where ActionType in ("FileCreated", "FileModified")
| project Timestamp, DeviceName, ActionType, FileName, InitiatingProcessCommandLine

// Detect modifications to SSH configuration
DeviceFileEvents
| where FileName == "/etc/ssh/sshd_config"
| where ActionType == "FileModified"
| project Timestamp, DeviceName, ActionType, FileName, InitiatingProcessCommandLine

// Detect execution of a Trojanized administrative command
DeviceProcessEvents
| where ProcessCommandLine contains "~/.local/bin/ls"
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// Detect execution of a SUID backdoor shell
DeviceProcessEvents
| where ProcessCommandLine contains "/tmp/rootbash"
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// Detect potential unauthorized logins
DeviceLogonEvents
| where AccountName contains "root" or AccountName contains "attacker"
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
- **Ensure that root login is normally restricted to detect deviations effectively.**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `January 30, 2025`  | `James Harrington`    |

