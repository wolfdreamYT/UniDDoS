# UniDDoS 

A DDoS script designed for DDoSing low to medium-scale WiFi networks and websites. Originally created as a prank for my mom, but it was evolved into a proper ddos tool.

> **Disclaimer:** I do not hold accountable for any damage or major scaled attacks in the future of uploading this. Use at your own risk.

---

##  Setup

### Requirements
- Python 3.13+
- pip 3.13+
- Node.js (for server testing)

### Install Dependencies
`pip install -r requirements.txt`

> This will automatically install all the required libraries.

---

##  How to Use

1. **Choose Your Target**
   - You can use an **IP** (e.g., `12.43.55.812`) or a **URL`.  
   - Make sure you have permission to test it.  

2. **Run the Program**

- A **UI window** will appear — this is your central command interface.

3. **Configure Attack Parameters**
- **Target:** IP or URL  
- **Number of Requests:** Set the amount, or leave empty for infinite/flood mode  
- **Threads:** Adjust from 5 to 100 depending on your computer’s capabilities  
- **Delay:** Set the interval between pings (default is rapid-fire)  

4. **Start & Stop**
- Click **Start** to begin the attack  
- Monitor the **traffic waves** in real-time  
- Click **Stop** to end the attack  

## Features

   - IP Source spoofing
   - IP DDoSer
   - unlimited amount of packets
   - unlimited amount of threads
   - allows to target specified ports
   - HTTP/HTTPS DDoSer

## Files

   - `happyday.py` = HTTP/HTTPS DDoSing
   - `sadday.py` = IP DDoSing
   - `web-testing.js` = Web Server (To test with)
---
