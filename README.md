# 🛡️ File Monitoring and Malware Detection Tool (VirusTotal Integrated)

A Python-based file monitoring and malware detection system that integrates with the VirusTotal API.  
This tool continuously observes system file changes (creation, modification, or deletion) and scans suspicious files for potential malware.  
It features a user-friendly **Tkinter GUI** to start/stop monitoring and view real-time logs.

---

## 🚀 Features

- 📁 **Real-time File Monitoring:** Tracks creation, modification, and deletion of files.
- 🧠 **VirusTotal Integration:** Automatically scans new or modified files via the VirusTotal API.
- 🧰 **Tkinter GUI Interface:** Start/Stop monitoring and view logs easily.
- 🧾 **Color-coded Logs:** Deleted files are shown in red for better visibility.
- ⚙️ **Customizable Paths:** Monitor specific folders or entire drives.
- 🔔 **Alert System:** Notifies when a file is flagged as malicious.

---

## 🧩 Tech Stack

- **Language:** Python  
- **Libraries:** `os`, `hashlib`, `requests`, `tkinter`, `watchdog`  
- **API:** VirusTotal API  

---

## 💻 How to Run

### 1. Clone this Repository
```bash
git clone https://github.com/yourusername/FileMonitoring_VirusTotal_GUI.git
cd FileMonitoring_VirusTotal_GUI
