# python-C-antivirus
SafetyWen Antivirus
SafetyWen is a Python & C++-based Windows antivirus system with real-time monitoring, YARA scanning, memory analysis, file integrity checking, and sandbox isolation. This project is open source and welcomes reference, modification, and extension.

## 🔍 Features
- 🧠 Process Monitoring: Detects and terminates malicious processes
- 🧬 Memory Scanning: Analyzes abnormal process memory behavior
- 📁 File Monitoring: Monitors file additions and modifications for immediate threat isolation
- 🧪 Sandbox Integration: Prioritizes sandboxing for threat analysis
- 🧹 Junk Cleaner: Cleans system junk and temporary files
- 🧰 GUI: Uses tkinter to provide a simple user interface
##⚙️ Installation
Please install Python 3.8 and or later and C++ and run the following command to install the necessary packages:

pip install psutil yara-python watchdog requests pywin32
And　install yara in https://github.com/VirusTotal/yara/releases
And you need to compile C++ files:g++ -shared -o scan.dll scan.cpp
