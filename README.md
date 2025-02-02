<img width="400" src="https://github.com/user-attachments/assets/0912ebf5-3d20-4966-b083-ebf02fbf0ff6"/>

# Threat Hunt Report: Unauthorized Persistence & Backdoor Creation

## Platforms and Languages Leveraged
- Linux (Ubuntu 22.04) Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Bash

## Scenario

Management has raised concerns about a soon-to-be-terminated employee potentially creating unauthorized backdoors and persistence mechanisms to maintain illicit access to company systems. Suspicious activity has been detected on the machine `thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`, where security teams suspect that multiple persistence techniques may have been deployed to retain unauthorized administrative control.

The objective is to identify and analyze unauthorized persistence mechanisms, detect Indicators of Compromise (IOCs), and assess the extent of the security breach. Immediate action will be taken to address any identified threats.

### High-Level IoC Discovery Plan

- **Check `DeviceFileEvents`** for modifications to `~/.ssh/authorized_keys`, systemd service files, and SUID binaries.
- **Check `DeviceProcessEvents`** for suspicious executions, including unauthorized system service modifications and Trojanized commands.
- **Check `DeviceLogonEvents`** for unusual remote login activity.

---

## Steps Taken

### 1. Searched the `DeviceProcessEvents` Table for SUID Backdoor Creation & Execution

**Objective:** Identify the creation and execution of a SUID backdoor (`/tmp/rootbash`) used for privilege escalation.

At **Feb 2, 2025 3:54:17 PM**, the user **"baddog"** executed the following command on the device **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"**:
```bash
sudo chown root:root /tmp/rootbash
```

This action modified the ownership of the backdoor binary, setting it up for privilege escalation.

Shortly after, at Feb 2, 2025 3:56:18 PM, the same user executed `/tmp/rootbash -p`. This confirms the successful execution of the backdoor, allowing privilege escalation to root.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where ProcessCommandLine contains "authorized_keys" or ProcessCommandLine contains "echo" or ProcessCommandLine contains "cat"
| project Timestamp, DeviceName, ActionType, ProcessCommandLine

DeviceProcessEvents
| where DeviceName == "thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where ProcessCommandLine contains "/tmp/rootbash"
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/3c1fabbb-7fc1-4978-a99c-763d777dc109">
---

### 2. Searched the `DeviceLogonEvents` Table

Searched for any `AccountName` that was not "baddog" to detect unauthorized SSH logins.

At **Feb 2, 2025 3:15:01 PM**, the user **"root"** logged into the device **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"** via **Network logon type**, indicating a remote SSH connection.

This suggests that a backdoor mechanism was used to gain unauthorized root access.

**Query used to locate event:**

```kql
DeviceLogonEvents
| where DeviceName == "thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where AccountName != "baddog"  // Look for unexpected SSH logins
| where LogonType in ("RemoteInteractive", "Network")
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/c6eb0196-2d43-4f1f-bd9a-8b7acf6862cd">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "labuser" actually opened the TOR browser.The results showed user “labuser” accessed tor.exe (tor browser), firefox.exe(tor browser) several times:

At 3:42:33 PM to 3:42:26 PM (within the same minute), multiple instances of the "firefox.exe" process were created. These processes, all related to the Tor Browser, were executed from C:\Users\labuser\Desktop\Tor Browser\Browser\firefox.exe with various command parameters to handle different processes related to the browser's content processing, tab management, utility tasks, and GPU handling. Each "firefox.exe" instance had its own set of parameters, such as channels, preferences, and other configuration settings related to how the browser should run.
The SHA256 hash for all instances of "firefox.exe" is the same: 3034311292fade8a24ab8e7312cfb7132153c14b9383439b527e8296fe06a492.

At 3:42:49 PM on January 20, 2025, the user "labuser" created a process called "tor.exe" on the device "hardmodevm." The process was located at C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe, with the SHA256 hash c3b431779278278cda8d2bf5de5d4da38025717630bfeae1a82c927d0703cd28. 


**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName  == "hardmodevm"
| where ProcessCommandLine has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName, Command = ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/785257b9-5e7c-4ce6-8bb2-f9f0c8c59f0f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. The results showed user “labuser” did indeed use tor to connect to an url.

At 3:43:03 PM on January 20, 2025, a successful connection was made by the user "labuser" from the device "hardmodevm" to the remote IP address 45.21.116.144 on port 9001. The connection was made using the file "tor.exe," and the remote URL accessed was https://www.35yt53tip6fr4hoov4a.com.


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName  == "hardmodevm"
| where InitiatingProcessAccountName == "labuser"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/f88b30e1-ccca-4a3a-b601-65992d08f1d3">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Time:** `3:29:50 PM, January 20, 2025`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.4.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-14.0.4.exe`

### 2. Process Execution - TOR Browser Installation

- **Time:** `3:30:55 PM, January 20, 2025`
- **Event:** The user "labuser" executed the file `tor-browser-windows-x86_64-portable-14.0.4.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `cmd.exe /c powershell.exe -ExecutionPolicy Bypass -Command "Start-Process \"C:\Downloads\tor-browser-windows-x86_64-portable-14.0.4.exe\" -ArgumentList '/S' -NoNewWindow -Wait".`
- **File Path:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Time:** `3:42:26 PM to 3:42:49 PM, January 20, 2025`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Time:** `3:43:03 PM, January 20, 2025`
- **Event:** A network connection to IP `45.21.116.144` on port `9001` by user "labuser" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Time:** `3:43:36 PM, January 20, 2025` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Time:** `3:51 to 3:55 PM, January 20, 2025`
- **Event:** The user "labuser" created a folder named `tor-shopping-list` on the desktop, and created several files with names that are potentially related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\labuser\Desktop\tor-shopping-list`

---

## Summary

The user "labuser" on the device "hardmodevm" installed and used the Tor Browser, taking actions that raised concerns. First, "labuser" silently initiated the installation of the Tor Browser through a PowerShell command. After the installation, they created the "tor.exe" file and executed it, which started the Tor service with specific configurations. Additionally, multiple instances of "firefox.exe" associated with the Tor Browser were launched, and the user successfully connected to the Tor network, accessing a remote IP and URL, suggesting the use of Tor for anonymous browsing. Furthermore, a folder (tor-shopping-list) containing several .txt and .json files was created, holding several files with names indicating potential illicit activity. These actions suggest that the user may have been engaging in suspicious or unauthorized activities using the Tor network.

---

## Response Taken

TOR usage was confirmed on the endpoint `hardmodevm` by the user `labuser`. The device was isolated, and the user's direct manager was notified.

---
