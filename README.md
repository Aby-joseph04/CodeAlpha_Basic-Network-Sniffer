# Basic Network Sniffer  

## 📌 Project Overview  
Developed a **simple Network Sniffer in Python** that captures and analyzes live network traffic on a Windows machine. The tool provides insights into packet structure, source/destination details, and payload data for better understanding of network behavior.  

---

## 🔑 Key Highlights  
- 📡 **Packet Capture** – Captures live packets using Python’s socket library.  
- 🌐 **Source & Destination Info** – Displays IP addresses and protocol details.  
- 📜 **Payload Display** – Shows raw packet data in a readable format.  
- ⏹ **Controlled Execution** – Can be stopped anytime with `Ctrl + C`.  

---

## 🛠 Tools & Libraries Used  
- 🐍 Python 3.13 (Windows 10/11)  
- 🔌 Socket Library (for raw packet sniffing)  
- ⚡ Scapy *(optional, for advanced packet analysis)*  

---

## 🚀 How to Run  
1. **Clone or download** this repository to your system.  
2. Open **Command Prompt** (or PowerShell) inside the project folder.  
3. Run the script:  
   ```bash
   python sniffer.py
