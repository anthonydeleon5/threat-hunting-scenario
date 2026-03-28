# <img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/> 

# Threat Hunt Report: Unauthorized TOR Usage

## Platforms and Languages Leveraged
- **Windows 11 Virtual Machines** (Microsoft Azure)
- **EDR Platform:** Microsoft Defender for Endpoint
- **Query Language:** Kusto Query Language (KQL)
- **Tool:** Tor Browser

## Scenario
Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks.

### High-Level TOR-Related IoC Discovery Plan
- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table
Searched for any file that had the string "tor" in it and discovered that the user **antadmin** on device **ant-vm-pro** downloaded a TOR installer. This activity began at **2026-03-27T7:55:01. Later, at **08:21:01, the user created a file called `tor-shopping-list.txt.txt` on the desktop.

**Query used to locate events:**
```kql
DeviceFileEvents
| where DeviceName == "ant-vm-pro"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-03-27T7:55:01)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, SHA256, Account = InitiatingProcessAccountName
```
<img width="1758" height="827" alt="1 File Activity Analysis" src="https://github.com/user-attachments/assets/56def340-8880-4a10-abbb-0be8d376cfb3" />

---

### 2. Searched the `DeviceProcessEvents` Table
Searched for the specific installer execution. Logs confirm that at **07:58:03, employee antadmin on the **ant-vm-pro** device ran the file `tor-browser-windows-x86_64-portable-15.0.8.exe` from their Downloads folder, using a command that triggered a silent installation (`/S`).

**Query used to locate event:**
```kql
DeviceProcessEvents
| where DeviceName == "ant-vm-pro"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.8.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, SHA256, ProcessCommandLine
```
<img width="1422" height="110" alt="2 Installer Execution" src="https://github.com/user-attachments/assets/12551612-b754-4bfd-a7ed-486d29fc6ee4" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution
Searched for evidence that the user actually launched the browser. At **07:58:52, the system recorded the launch of `firefox.exe` (the TOR browser shell) followed by `tor.exe` (the proxy service).

**Query used to locate events:**
```kql
DeviceProcessEvents
| where DeviceName == "ant-vm-pro"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections
Searched for traffic on known TOR ports. At **08:01:16, the device successfully established a connection to a remote relay at **109.104.155.20** on port **9001**. The connection was initiated by `tor.exe`.

**Query used to locate events:**
```kql
DeviceNetworkEvents
| where DeviceName == "ant-vm-pro"
| where RemotePort in ("9040", "9030", "9001", "9050", "9051", "9150")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="1857" height="315" alt="4 Network Connection Identification" src="https://github.com/user-attachments/assets/f920c61a-7604-4724-9add-8f7443e53540" />

---

## Chronological Event Timeline

### 1. File Download - TOR Installer
- **Timestamp:** `2026-03-27T07:55:01Z`
- **Event:** User `antadmin` downloaded `tor-browser-windows-x86_64-portable-15.0.8.exe`.
- **Action:** File download detected.

### 2. Process Execution - TOR Browser Installation
- **Timestamp:** `2026-03-27T07:58:03Z`
- **Event:** User `antadmin` executed the installer in silent mode (`/S`).
- **Action:** Process creation detected.

### 3. Process Execution - TOR Browser Launch
- **Timestamp:** `2026-03-27T07:58:52Z`
- **Event:** User `antadmin` opened the TOR browser; `firefox.exe` and `tor.exe` were created.
- **Action:** Process creation of TOR browser-related executables.

### 4. Network Connection - TOR Network
- **Timestamp:** `2026-03-28T08:01:16Z`
- **Event:** Connection to IP `109.104.155.20` on port `9001` established.
- **Action:** Connection success.

### 5. File Creation - TOR Shopping List
- **Timestamp:** `2026-03-28T08:21:01Z`
- **Event:** User `antadmin` created `tor-shopping-list.txt.txt` on the desktop.
- **Action:** File creation detected.

---

## Summary
The user **antadmin** on the **ant-vm-pro** device successfully installed and used the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created a file named `tor-shopping-list.txt.txt` on their desktop. This sequence indicates that the user actively used the TOR browser for anonymous browsing and documented their activities.

---

## Response Taken
TOR usage was confirmed on the endpoint **ant-vm-pro** by the user **antadmin**. The device was isolated, and the user's direct manager was notified.
