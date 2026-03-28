# Threat Hunt Report: Unauthorized TOR Browser Activity
    
    ## Incident Overview
    On March 27, 2026, network security monitoring detected anomalous encrypted traffic patterns originating from the workstation **ant-vm-pro**. These patterns were consistent with connections to known TOR entry nodes, suggesting a potential circumvention of organizational security controls. An investigation was initiated to identify the source of the traffic, confirm the installation of unauthorized software, and document the scope of the user's activity.
    
    ### Investigative Methodology
    The hunt focused on the following Indicators of Compromise (IoCs):
    * **File System Analysis:** Searching `DeviceFileEvents` for TOR-related installers and suspicious text files created on the desktop.
    * **Process Execution:** Analyzing `DeviceProcessEvents` for silent installation flags (`/S`) and the execution of the `tor.exe` binary.
    * **Network Traffic:** Correlating `DeviceNetworkEvents` with known TOR relay ports (9001, 9050, etc.) to confirm active circuit establishment.
    
    ---
    
    ## Chronological Investigation Findings
    
    ### 1. Discovery of Unauthorized Installer
    At **23:55:01Z**, the account `antadmin` was identified downloading the TOR portable installer. This file was staged in the user's Downloads directory and later renamed.
    
    **Query:**
    ```kql
    DeviceFileEvents
    | where DeviceName == "ant-vm-pro"
    | where FileName contains "tor-browser-windows-x86_64-portable-15.0.8.exe"
    | project Timestamp, DeviceName, ActionType, FileName, SHA256, Account = InitiatingProcessAccountName
    ```
    
    ---
    
    ### 2. Evidence of Silent Installation
    At **23:58:03Z**, logs confirmed the installer was executed using the `/S` flag. This indicates a deliberate attempt to install the software silently and bypass standard user prompts. Shortly after, at **23:58:14Z**, the system recorded the extraction of the core proxy executable `tor.exe`.
    
    **Query:**
    ```kql
    DeviceProcessEvents
    | where DeviceName == "ant-vm-pro"
    | where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.8.exe /S"
    | project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
    ```
    
    ---
    
    ### 3. Confirmation of TOR Browser Launch
    By **23:58:52Z**, the system recorded the successful launch of the TOR browser shell (`firefox.exe`) followed by the initialization of the proxy service (`tor.exe`) to manage the encrypted circuit.
    
    **Query:**
    ```kql
    DeviceProcessEvents
    | where DeviceName == "ant-vm-pro"
    | where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
    | project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
    | order by Timestamp desc
    ```
    <img width="1758" height="827" alt="3 Browser Launch Verification" src="https://github.com/user-attachments/assets/8812302f-8db6-4613-b6a1-d2ac95113cc1" />
    
    ---
    
    ### 4. Verified Connection to TOR Network
    The investigation confirmed an active TOR circuit at **00:01:16Z** on March 28. The workstation established a successful connection to a remote relay at **109.104.155.20** over port **9001**.
    
    **Query:**
    ```kql
    DeviceNetworkEvents
    | where DeviceName == "ant-vm-pro"
    | where RemotePort in ("9040", "9030", "9001", "9050", "9051", "9150")
    | project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName
    | order by Timestamp desc
    ```
    <img width="1857" height="315" alt="4 Network Connection Identification" src="https://github.com/user-attachments/assets/f920c61a-7604-4724-9add-8f7443e53540" />
    
    ---
    
    ### 5. Artifact Retrieval: "Shopping List"
    During the unauthorized session, at **00:21:01Z**, the user created a file named `tor-shopping-list.txt.txt` on the desktop. This file is considered a high-priority artifact for further forensic analysis regarding user intent.
    
    **Query:**
    ```kql
    DeviceFileEvents
    | where DeviceName == "ant-vm-pro"
    | where FileName contains "tor-shopping-list.txt"
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath
    ```
    
    ---
    
    ## Summary
    The investigation confirmed that the user `antadmin` on workstation `ant-vm-pro` successfully bypassed security policy by installing TOR Browser **v15.0.8**. The subject utilized a silent installation method and established verified external connections to the TOR network. The creation of a "shopping list" file on the desktop confirms active interaction with the software.
    
    ## Response Taken
    * **Host Isolation:** Workstation `ant-vm-pro` was immediately isolated from the production network.
    * **Management Notification:** The user's direct manager was notified of the unauthorized activity.
    * **Evidence Preservation:** All logs and the `tor-shopping-list.txt.txt` artifact were preserved for further review.
    
