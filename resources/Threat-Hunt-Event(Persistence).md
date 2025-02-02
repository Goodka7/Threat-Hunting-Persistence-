# Threat Event (Persistence & Backdoor Access)

## Steps the "Bad Actor" took to Create Logs and IoCs:

1. Created a rogue SSH key for persistent access by modifying `~/.ssh/authorized_keys`.
2. Modified `/etc/ssh/sshd_config` to allow root login.
3. Created a hidden cron job for remote command execution.
4. Deployed a persistent backdoor by adding a malicious systemd service.
5. Restarted the SSH service (`systemctl restart sshd`).

---

## Tables Used to Detect IoCs:

| **Parameter** | **Description** |
|--------------|----------------|
| **Name** | DeviceProcessEvents |
| **Info** | [Microsoft Documentation](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| **Purpose** | Used to detect unauthorized SSH key additions, cron job modifications, and suspicious system processes. |

| **Name** | DeviceFileEvents |
|--------------|----------------|
| **Info** | [Microsoft Documentation](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) |
| **Purpose** | Used to detect modifications to `~/.ssh/authorized_keys`, `/etc/ssh/sshd_config`, and systemd service files. |

| **Name** | DeviceLogonEvents |
|--------------|----------------|
| **Info** | [Microsoft Documentation](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table) |
| **Purpose** | Used to detect unauthorized remote logins or unusual authentication patterns. |

---

## Related Queries:

```kql
// Detect unauthorized SSH key additions
DeviceFileEvents
| where FileName == "~/.ssh/authorized_keys"
| where ActionType in ("FileCreated", "FileModified")
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine

// Detect modifications to SSH configuration
DeviceFileEvents
| where FileName == "/etc/ssh/sshd_config"
| where ActionType == "FileModified"
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine

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

