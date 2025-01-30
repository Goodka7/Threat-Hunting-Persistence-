# Threat Event (Unauthorized Privilege Escalation)
**Unauthorized Privilege Escalation & Persistence**

## Steps the "Bad Actor" took to Create Logs and IoCs:
1. Attempted to escalate privileges using `sudo -l` to check for accessible privileges.
2. Modified the `/etc/sudoers` file to allow passwordless escalation.
3. Added a new user to the `sudo` group using `usermod -aG sudo attacker`.
4. Modified SSH settings (`/etc/ssh/sshd_config`) to allow root login.
5. Restarted the SSH service (`systemctl restart sshd`).
6. Attempted to clean up logs using `echo "" > ~/.bash_history`.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table|
| **Purpose**| Used to detect `sudo -l` execution, privilege escalation attempts, and `usermod` commands. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table|
| **Purpose**| Used to detect modifications to `/etc/sudoers`, `/etc/passwd`, and `/etc/group`. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceLogonEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table|
| **Purpose**| Used to detect unauthorized root logins via SSH. |

---

## Related Queries:
```kql
// Detect privilege escalation attempts
DeviceProcessEvents
| where ProcessCommandLine contains "sudo"
| where ActionType in ("ProcessCreated", "ProcessExecuted")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Detect unauthorized modifications to system files
DeviceFileEvents
| where FileName in ("/etc/sudoers", "/etc/passwd", "/etc/group", "/etc/shadow")
| where ActionType in ("FileModified", "FileCreated")
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine

// Detect potential unauthorized logins
DeviceLogonEvents
| where AccountName contains "root" or AccountName contains "admin"
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

