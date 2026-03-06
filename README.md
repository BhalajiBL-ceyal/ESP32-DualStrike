# ESP32 Dual-Node Wi-Fi Pen-Tool

Inspired by [risinek/esp32-wifi-penetration-tool](https://github.com/risinek/esp32-wifi-penetration-tool), but redesigned for **two ESP32s** connected by **ESP-NOW** to solve the fundamental problem of the single-board design:
<img width="1915" height="967" alt="image" src="https://github.com/user-attachments/assets/ee2bac00-d1ca-4c5c-b593-3b2dedcece8a" />

> 🚨 When the ESP32 enters **monitor/promiscuous mode** it can no longer run an Access Point or WebServer — the radio is fully consumed by packet sniffing.  
> The dual-node design splits responsibilities so **both functions work simultaneously**.

---

## Architecture

```
┌───────────────────────────────────────────────────────────────┐
│  YOUR PHONE / LAPTOP                                          │
│  Connected to "ESP32-PenTool" Wi-Fi                           │
│  Browser  http://192.168.4.1                                  │
└──────────────────────┬────────────────────────────────────────┘
                       │  Wi-Fi (HTTP + WebSocket port 81)
                       ▼
┌──────────────────────────────────┐
│         NODE 1 — ESP32           │
│  Node1_Gateway/Node1_Gateway.ino │
│  • Wi-Fi AP  "ESP32-PenTool"     │
│  • HTTP server  (port 80) UI     │
│  • WebSocket   (port 81) cmds    │
│  • Sends cmds → Node2 ESP-NOW    │
│  • Receives results ← Node2      │
└─────────────────┬────────────────┘
                  │  ESP-NOW (802.11 management frames)
                  │  ≈ 250 m range, no AP connection needed
                  ▼
┌─────────────────────────────────────────┐
│         NODE 2 — ESP32                  │
│Node2_AttackEngine/Node2_AttackEngine.ino│
│  • Monitor / promiscuous mode           │
│  • Deauth / SAE / SA-Query              │
│  • Beacon Spam                          │
│  • Evil Twin + Captive Portal           │
│  • WPA Handshake / PMKID cap.           │
│  • Port Scan / Wardriving               │
└─────────────────────────────────────────┘
```

---

## Features

| Feature | Description |
|---|---|
| **Monitor Mode** | Packet counter + RSSI/channel stats per second |
| **Deauth Flood** | Deauth + Disassoc on any channel, optional target client |
| **Beacon Spam** | 15 rotating fake SSIDs every 80ms |
| **Evil Twin** | Open AP clone + captive portal credential capture |
| **WPA Handshake** | Full EAPOL 4-way capture → `.cap` download (Hashcat/Aircrack) |
| **PMKID Attack** | Clientless WPA2 PMKID capture |
| **SAE Flood** | WPA3 SAE Commit exhaustion |
| **SA-Query Flood** | PMF Management Frame flooding (WPA2/WPA3) |
| **Assoc Flood** | Association Response flood (exploits buggy clients) |
| **Port Scan** | TCP port sweep against any IP |
| **Wardriving** | Passive scan cycles ch1-13, logs all APs found |

---

## Setup (Step-by-Step)

### Hardware Required
- 2× ESP32 development boards (any variant)
- USB cables for programming

### Software Required
- [Arduino IDE 2.x](https://www.arduino.cc/en/software)
- **ESP32 board package** by Espressif (v3.x)  
  *File → Preferences → Board Manager URL:*  
  `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json`
- **WebSockets library** by Markus Sattler (≥ 2.4.1)  
  *Tools → Manage Libraries → search "WebSockets" → install Markus Sattler version*

---

### Step 1 — Programme Node 2 first

1. Open `Node2_AttackEngine/Node2_AttackEngine.ino` in Arduino IDE
2. Select your **ESP32 board** and the correct **COM port**
3. Upload the sketch
4. Open **Serial Monitor** (115200 baud)
5. Note the **"My STA MAC:"** address printed at boot, e.g.:
   ```
   ╔══════════════════════════════════════════════╗
   ║  My STA MAC: 78:21:84:E1:76:10               ║
   ║  → Paste above into esp1.ino  ESP2_MAC[]     ║
   ╚══════════════════════════════════════════════╝
   ```

---

### Step 2 — Programme Node 1

1. Open `Node1_Gateway/Node1_Gateway.ino` in Arduino IDE
2. Paste Node 2's STA MAC into `ESP2_MAC[]`:
   ```cpp
   uint8_t ESP2_MAC[] = {0x78, 0x21, 0x84, 0xE1, 0x76, 0x10};
   ```
3. Select your **ESP32 board** + COM port (different port to Node 2)
4. Upload the sketch
5. Open **Serial Monitor** for Node 1 — note the **"AP  MAC:"** address, e.g.:
   ```
   AP  MAC: E0:5A:1B:75:D1:05
   ```

---

### Step 3 — Update Node 2 with Node 1's AP MAC

1. Open `Node2_AttackEngine/Node2_AttackEngine.ino`
2. Paste Node 1's **AP MAC** into `ESP1_MAC[]`:
   ```cpp
   uint8_t ESP1_MAC[] = {0xE0, 0x5A, 0x1B, 0x75, 0xD1, 0x05};
   ```
3. Re-upload to Node 2

---

### Step 4 — Connect and Use

1. Power both ESP32s (USB or battery)
2. On your phone/laptop, connect to Wi-Fi: **`ESP32-PenTool`** / password **`pentest1`**
3. Open browser → `http://192.168.4.1`
4. The **Node2: ON** badge should appear green (heartbeat confirmed)
5. Use the tabbed UI to run any attack:
   - Click **Scan APs** first to populate dropdowns
   - Select target AP → click the attack button

---

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| Node2 badge stays red | Wrong MAC pasted | Re-check ESP1_MAC[] / ESP2_MAC[], power-cycle both |
| "ESP-NOW send failed (0x3066)" | Channel mismatch | Both nodes broadcast on ch 1; ensure nothing changed |
| Scan returns 0 APs | Interference | Try again; scan disables Wi-Fi driver briefly |
| Deauth has no effect | AP has 802.11w PMF | Use SA-Query or SAE Flood tabs instead |
| PCAP download broken | < 4 EAPOL frames | Wait longer or repeat scan+deauth to force reassociation |
| Evil Twin: clients don't connect | Wrong SSID | Make sure the deauth is running on same target channel |

---

## Cracking Handshakes

After downloading `handshake.cap`:

```bash
# Convert to hccapx for Hashcat
cap2hccapx handshake.cap handshake.hccapx

# Crack with Hashcat (WPA2)
hashcat -m 22000 handshake.hccapx wordlist.txt

# Or with Aircrack-ng
aircrack-ng handshake.cap -w wordlist.txt
```

---

## Legal Disclaimer

> ⚠️ **For educational and authorised penetration testing ONLY.**  
> Using these tools on networks you do not own or have **explicit written permission** to test is illegal in most jurisdictions and may result in criminal prosecution.  
> The author accepts no liability for misuse.


