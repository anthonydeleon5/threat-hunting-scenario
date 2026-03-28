# Threat Event (Unauthorized TOR Usage)
**Unauthorized TOR Browser Installation and Use**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Download: Downloaded the portable TOR installer: tor-browser-windows-x86_64-portable-15.0.8.exe.
2. Silent Install: Executed the installer with the silent switch: tor-browser-windows-x86_64-portable-15.0.8.exe /S.
3. Launch: Opened the TOR browser (firefox.exe), which spawned the tor.exe proxy process.
4. Browse: Successfully connected to a TOR relay at 109.104.155.20 on port 9001.
5. Exfiltrate/Log: Created a file on the desktop named tor-shopping-list.txt.txt to log activities.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting TOR download and installation, as well as the shopping list creation. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of TOR as well as the TOR browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect TOR network activity, specifically tor.exe and firefox.exe making connections over ports to be used by TOR (9001, 9030, 9040, 9050, 9051, 9150).|

---

## Related Queries:
```kql
// 1. Detect the installer being downloaded or created
DeviceFileEvents
| where DeviceName == "ant-vm-pro"
| where FileName contains "tor-browser-windows-x86_64-portable-15.0.8.exe"
| project Timestamp, DeviceName, ActionType, FileName, SHA256, Account = InitiatingProcessAccountName

// 2. Detect the silent installation process execution
DeviceProcessEvents
| where DeviceName == "ant-vm-pro"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.8.exe /S"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, AccountName, ProcessCommandLine

// 3. Detect the launch of the TOR Browser and its proxy service
DeviceProcessEvents
| where DeviceName == "ant-vm-pro"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine
| order by Timestamp desc

// 4. Detect successful network connections to TOR relays
DeviceNetworkEvents
| where DeviceName == "ant-vm-pro"
| where RemotePort in ("9040", "9030", "9001", "9050", "9051", "9150")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName
| order by Timestamp desc

// 5. Detect the creation of the "shopping list" file
DeviceFileEvents
| where DeviceName == "ant-vm-pro"
| where FileName contains "tor-shopping-list.txt"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath
```

---

## Created By:
- **Author Name**: Anthony De Leon
- **Author Contact**: https://www.linkedin.com/in/anthonydeleon5/
- **Date**: March 28, 2026

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `March  28, 2026`  | `Anthony De Leon`   
