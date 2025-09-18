# BLE Scanner & Raw Communication Tool

Cross-platform desktop GUI for working with Bluetooth Low Energy (BLE).  
Supports scanning, connecting, reading/writing, fuzzing, and advertising/emulation (depending on OS).


<img width="1920" height="1040" alt="image" src="https://github.com/user-attachments/assets/77a166e9-5286-4c48-978b-bb3b2f2fcd47" />


---

A cross-platform Tkinter GUI for Bluetooth Low Energy (BLE) that lets you:

- Scan and list nearby BLE devices (with RSSI)
- Connect to a device and enumerate **GATT services & characteristics**
- **Read**, **write**, and **subscribe (notify)** on characteristics
- Run a **payload fuzzer/spammer** with patterns, size limits, and rate control
- Capture HCI activity on Linux via **`btmon`** (or advertisement logging on Windows)
- On Linux, tweak adapter **MAC/privacy** (static random, privacy/resolvable; public address where supported)

---

## Table of Contents

- [Supported Platforms](#supported-platforms)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Linux / Raspberry Pi OS](#linux--raspberry-pi-os)
  - [Windows 10/11](#windows-1011)
- [Running the App](#running-the-app)
- [GUI Overview](#gui-overview)
- [Usage Guide](#usage-guide)
  - [1) Scan & Connect](#1-scan--connect)
  - [2) Services & Characteristics](#2-services--characteristics)
  - [3) Read / Write / Notifications](#3-read--write--notifications)
  - [4) Fuzzer / Spammer](#4-fuzzer--spammer)
  - [5) Sniffer](#5-sniffer)
  - [6) MAC & Privacy (Linux)](#6-mac--privacy-linux)
- [Data Input Formats](#data-input-formats)
- [Troubleshooting](#troubleshooting)
- [Security & Responsible Use](#security--responsible-use)
- [Architecture & Internals](#architecture--internals)
- [Extending](#extending)
- [License](#license)

---

## Supported Platforms

- **Linux / Raspberry Pi OS (Debian family)** — BlueZ backend (DBus)
- **Windows 10/11** — WinRT backend through Bleak

> macOS is not targeted by this script as written.

---

## Requirements

- **Python**: 3.10+  
- **Python packages**:  
  - [`bleak`](https://pypi.org/project/bleak/)
  - `tkinter` (bundled with most OS Python builds)
  - Standard library modules used: `asyncio`, `threading`, `subprocess`, etc.
- **Linux utilities (optional but recommended)**: `btmon`, `btmgmt`, `hciconfig`, `bdaddr` (where available), `wireshark`/`tshark`

---

## Installation

### Linux / Raspberry Pi OS

```bash
sudo apt update
# Core system dependencies
sudo apt install -y python3 python3-pip python3-tk bluetooth bluez

# Optional tools used by the app
sudo apt install -y btmon bluez-hcidump wireshark tshark \
                    bluez-test-scripts || true

# (Recommended) use a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Python dependencies
python3 -m pip install --upgrade pip
pip install bleak
