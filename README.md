# BLE Scanner & Raw Communication Tool

Cross-platform desktop GUI for working with Bluetooth Low Energy (BLE).  
Supports scanning, connecting, reading/writing, fuzzing, and advertising/emulation (depending on OS).


<img width="1920" height="1040" alt="image" src="https://github.com/user-attachments/assets/77a166e9-5286-4c48-978b-bb3b2f2fcd47" />


---

## ✨ Features

- **Device Scanner**
  - Discover nearby BLE devices
  - View RSSI and device name
  - Connect to selected device

- **Service & Characteristic Explorer**
  - Browse GATT services and characteristics
  - Read and write data
  - Enable notifications

- **Raw Communication**
  - Send arbitrary payloads in text, decimal, or hex formats
  - View responses in hex and UTF-8

- **Protocol Fuzzer / Spammer**
  - Patterns: zeros, ones, increment, walking-bit, random
  - Adjustable packet length, rate, and iteration limits
  - Supports write with/without response

- **Broadcast / Emulator**
  - **Windows**: BLE advertising (via WinRT `winsdk`)
  - **Linux (BlueZ)**: advertising + minimal GATT server with read/write/notify

---

## 🖥️ Requirements

- **Python** 3.10 – 3.12 (64-bit recommended)
- Packages:
  ```bash
  pip install bleak winsdk dbus-next
