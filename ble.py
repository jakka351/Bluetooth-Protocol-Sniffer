import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import asyncio
import threading
import time
from datetime import datetime
from bleak import BleakScanner, BleakClient
from bleak.backends.device import BLEDevice
from bleak.backends.service import BleakGATTService
from bleak.backends.characteristic import BleakGATTCharacteristic
import logging
import os
import re
import random
import subprocess
import shlex
import sys
from typing import Optional, List

IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")

# -----------------------------
# Utility helpers (non-GUI)
# -----------------------------
def which(cmd: str) -> Optional[str]:
    for p in os.environ.get("PATH", "").split(os.pathsep):
        cand = os.path.join(p, cmd)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None

def is_valid_mac(mac: str) -> bool:
    return re.fullmatch(r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}", mac) is not None

def gen_static_random_mac() -> str:
    # BLE "static random": top two bits of first octet must be 1
    b = [random.randint(0, 255) for _ in range(6)]
    b[0] = (b[0] & 0x3F) | 0xC0
    return ":".join(f"{x:02X}" for x in b)

def iface_to_index(iface: str) -> Optional[str]:
    m = re.match(r"hci(\d+)$", iface)
    return m.group(1) if m else None

# -----------------------------
# Main App
# -----------------------------
class BLEApp:
    def __init__(self, root):
        self.root = root
        self.root.title("BLE Scanner and Raw Communication Tool")
        self.root.geometry("1400x900")

        # BLE state
        self.scanner = None
        self.client: Optional[BleakClient] = None
        self.connected_device: Optional[BLEDevice] = None
        self.is_scanning = False
        self.devices: dict[str, BLEDevice] = {}
        self.services: dict[str, BleakGATTService] = {}
        self.characteristics: dict[str, BleakGATTCharacteristic] = {}
        self.selected_characteristic: Optional[BleakGATTCharacteristic] = None

        # Async plumbing
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.thread: Optional[threading.Thread] = None

        # Fuzzer state
        self.fuzz_running = False
        self.fuzz_task: Optional[asyncio.Future] = None

        # Sniffer state
        self.sniffer_proc: Optional[subprocess.Popen] = None   # Linux btmon
        self.sniffer_thread: Optional[threading.Thread] = None
        self.sniffer_stop = threading.Event()
        self.sniff_scanner = None                              # Windows soft sniffer
        self.sniff_task: Optional[asyncio.Future] = None

        self.setup_gui()
        self.setup_ble()

    # -----------------------------
    # GUI
    # -----------------------------
    def setup_gui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        for c in range(3):
            main_frame.columnconfigure(c, weight=1)
        main_frame.rowconfigure(0, weight=1)

        # Left panel — Scanner
        left_frame = ttk.LabelFrame(main_frame, text="BLE Device Scanner", padding="5")
        left_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.scan_button = ttk.Button(left_frame, text="Start Scan", command=self.toggle_scan)
        self.scan_button.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(left_frame, text="Discovered Devices:").grid(row=1, column=0, sticky="w")

        device_frame = ttk.Frame(left_frame)
        device_frame.grid(row=2, column=0, sticky="nsew", pady=(5, 8))
        self.device_listbox = tk.Listbox(device_frame, height=12, width=48)
        device_scrollbar = ttk.Scrollbar(device_frame, orient="vertical", command=self.device_listbox.yview)
        self.device_listbox.configure(yscrollcommand=device_scrollbar.set)
        self.device_listbox.grid(row=0, column=0, sticky="nsew")
        device_scrollbar.grid(row=0, column=1, sticky="ns")
        device_frame.columnconfigure(0, weight=1)
        device_frame.rowconfigure(0, weight=1)
        self.connect_button = ttk.Button(left_frame, text="Connect to Selected", command=self.connect_device)
        self.connect_button.grid(row=3, column=0, sticky="ew", pady=(0, 8))

        ttk.Label(left_frame, text="Services:").grid(row=4, column=0, sticky="w")
        service_frame = ttk.Frame(left_frame)
        service_frame.grid(row=5, column=0, sticky="nsew")
        self.service_listbox = tk.Listbox(service_frame, height=10, width=48)
        service_scrollbar = ttk.Scrollbar(service_frame, orient="vertical", command=self.service_listbox.yview)
        self.service_listbox.configure(yscrollcommand=service_scrollbar.set)
        self.service_listbox.bind('<<ListboxSelect>>', self.on_service_select)
        self.service_listbox.grid(row=0, column=0, sticky="nsew")
        service_scrollbar.grid(row=0, column=1, sticky="ns")
        service_frame.columnconfigure(0, weight=1)
        service_frame.rowconfigure(0, weight=1)
        left_frame.columnconfigure(0, weight=1)
        left_frame.rowconfigure(5, weight=1)

        # Middle panel — Characteristics & IO
        mid = ttk.LabelFrame(main_frame, text="Characteristics & Communication", padding=5)
        mid.grid(row=0, column=1, sticky="nsew", padx=(0, 8))
        ttk.Label(mid, text="Characteristics:").grid(row=0, column=0, sticky="w")
        char_frame = ttk.Frame(mid)
        char_frame.grid(row=1, column=0, sticky="nsew", pady=(5, 8))
        self.char_listbox = tk.Listbox(char_frame, height=10, width=48)
        char_scrollbar = ttk.Scrollbar(char_frame, orient="vertical", command=self.char_listbox.yview)
        self.char_listbox.configure(yscrollcommand=char_scrollbar.set)
        self.char_listbox.bind('<<ListboxSelect>>', self.on_characteristic_select)
        self.char_listbox.grid(row=0, column=0, sticky="nsew")
        char_scrollbar.grid(row=0, column=1, sticky="ns")
        char_frame.columnconfigure(0, weight=1)
        char_frame.rowconfigure(0, weight=1)

        # Raw data box
        ttk.Label(mid, text="Raw Data Communication:").grid(row=2, column=0, sticky="w", pady=(6, 2))
        ttk.Label(mid, text="Formats: 'Hello', '01,02,03', '0x41,0x42'").grid(row=3, column=0, sticky="w")
        self.data_entry = tk.Text(mid, height=4, width=48)
        self.data_entry.grid(row=4, column=0, sticky="ew", pady=(2, 4))
        btns = ttk.Frame(mid); btns.grid(row=5, column=0, sticky="ew", pady=(2, 8))
        ttk.Button(btns, text="Send Raw Data", command=self.send_raw_data).grid(row=0, column=0, sticky="ew", pady=2)
        ttk.Button(btns, text="Read Characteristic", command=self.read_characteristic).grid(row=1, column=0, sticky="ew", pady=2)
        ttk.Button(btns, text="Enable Notifications", command=self.enable_notifications).grid(row=2, column=0, sticky="ew", pady=2)
        ttk.Button(btns, text="Disconnect", command=self.disconnect_device).grid(row=3, column=0, sticky="ew", pady=2)
        btns.columnconfigure(0, weight=1)

        # Fuzzer
        fuzz = ttk.LabelFrame(mid, text="Protocol Fuzzer / Spammer (use responsibly)", padding=5)
        fuzz.grid(row=6, column=0, sticky="ew", pady=(6, 4))
        row = 0
        ttk.Label(fuzz, text="Pattern").grid(row=row, column=0, sticky="w")
        self.fuzz_pattern = ttk.Combobox(fuzz, values=["zeros","ones","increment","walking-bit","random"], state="readonly")
        self.fuzz_pattern.set("increment"); self.fuzz_pattern.grid(row=row, column=1, sticky="ew"); row += 1
        ttk.Label(fuzz, text="Min Len").grid(row=row, column=0, sticky="w")
        self.fuzz_min = ttk.Spinbox(fuzz, from_=0, to=512, width=6); self.fuzz_min.set(0); self.fuzz_min.grid(row=row, column=1, sticky="w"); row += 1
        ttk.Label(fuzz, text="Max Len").grid(row=row, column=0, sticky="w")
        self.fuzz_max = ttk.Spinbox(fuzz, from_=1, to=512, width=6); self.fuzz_max.set(32); self.fuzz_max.grid(row=row, column=1, sticky="w"); row += 1
        ttk.Label(fuzz, text="Rate (pps)").grid(row=row, column=0, sticky="w")
        self.fuzz_rate = ttk.Spinbox(fuzz, from_=1, to=500, width=6); self.fuzz_rate.set(50); self.fuzz_rate.grid(row=row, column=1, sticky="w"); row += 1
        self.fuzz_write_no_resp = tk.BooleanVar(value=True)
        ttk.Checkbutton(fuzz, text="Write Without Response", variable=self.fuzz_write_no_resp).grid(row=row, column=0, columnspan=2, sticky="w"); row += 1
        self.fuzz_limit_iters = ttk.Spinbox(fuzz, from_=1, to=1000000, width=10); self.fuzz_limit_iters.set(1000)
        ttk.Label(fuzz, text="Max Packets").grid(row=row, column=0, sticky="w")
        self.fuzz_limit_iters.grid(row=row, column=1, sticky="w"); row += 1
        fb = ttk.Frame(fuzz); fb.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(4,0))
        ttk.Button(fb, text="Start Fuzz", command=self.start_fuzzer).grid(row=0, column=0, sticky="ew")
        ttk.Button(fb, text="Stop", command=self.stop_fuzzer).grid(row=0, column=1, sticky="ew")
        fb.columnconfigure(0, weight=1); fb.columnconfigure(1, weight=1)
        mid.columnconfigure(0, weight=1); mid.rowconfigure(1, weight=1)

        # Right panel — Log + Sniffer + MAC
        right = ttk.LabelFrame(main_frame, text="Communication Log", padding=5)
        right.grid(row=0, column=2, sticky="nsew")
        log_controls = ttk.Frame(right); log_controls.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        ttk.Button(log_controls, text="Clear Log", command=self.clear_log).grid(row=0, column=0, sticky="w")
        self.log_text = scrolledtext.ScrolledText(right, height=30, width=70, bg="black", fg="lime", font=("Courier", 9))
        self.log_text.grid(row=1, column=0, sticky="nsew")
        right.columnconfigure(0, weight=1); right.rowconfigure(1, weight=1)

        # Sniffer (Linux: btmon / Windows: soft scanner)
        sniff = ttk.LabelFrame(right, text=("HCI Sniffer (btmon)" if IS_LINUX else "Soft Sniffer (Advertisements)"), padding=5)
        sniff.grid(row=2, column=0, sticky="ew", pady=(6, 4))
        if IS_LINUX:
            ttk.Label(sniff, text="Interface (e.g., hci0)").grid(row=0, column=0, sticky="w")
            self.sniff_iface = ttk.Entry(sniff, width=10); self.sniff_iface.insert(0, "hci0"); self.sniff_iface.grid(row=0, column=1, sticky="w")
            self.sniff_path = tk.StringVar(value=os.path.expanduser("~/ble_radar/ble_sniff.log"))
            ttk.Label(sniff, text="Log file").grid(row=1, column=0, sticky="w")
            ttk.Entry(sniff, textvariable=self.sniff_path, width=42).grid(row=1, column=1, sticky="ew")
        else:
            self.sniff_path = tk.StringVar(value=os.path.expanduser("~/ble_radar/adv_sniff.log"))
            ttk.Label(sniff, text="Windows can’t HCI-sniff without drivers; logging advertisements instead.").grid(row=0, column=0, columnspan=2, sticky="w")
            ttk.Label(sniff, text="Log file").grid(row=1, column=0, sticky="w")
            ttk.Entry(sniff, textvariable=self.sniff_path, width=42).grid(row=1, column=1, sticky="ew")
        sb = ttk.Frame(sniff); sb.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(4,0))
        ttk.Button(sb, text="Start Sniffer", command=self.start_sniffer).grid(row=0, column=0, sticky="ew")
        ttk.Button(sb, text="Stop Sniffer", command=self.stop_sniffer).grid(row=0, column=1, sticky="ew")
        sb.columnconfigure(0, weight=1); sb.columnconfigure(1, weight=1)

        # MAC tools
        macf = ttk.LabelFrame(right, text="MAC Address Tools", padding=5)
        macf.grid(row=3, column=0, sticky="ew", pady=(6, 0))
        ttk.Label(macf, text="Interface").grid(row=0, column=0, sticky="w")
        self.mac_iface = ttk.Entry(macf, width=10); self.mac_iface.insert(0, "hci0"); self.mac_iface.grid(row=0, column=1, sticky="w")
        ttk.Label(macf, text="MAC").grid(row=1, column=0, sticky="w")
        self.mac_value = ttk.Entry(macf, width=18); self.mac_value.insert(0, gen_static_random_mac()); self.mac_value.grid(row=1, column=1, sticky="w")
        mb = ttk.Frame(macf); mb.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(4,0))
        self.btn_gen = ttk.Button(mb, text="Generate Static Random", command=lambda: self.mac_value.delete(0, tk.END) or self.mac_value.insert(0, gen_static_random_mac()))
        self.btn_static = ttk.Button(mb, text="Set Static Random (btmgmt)", command=self.mac_set_static)
        self.btn_priv = ttk.Button(mb, text="Enable Privacy (Resolvable)", command=self.mac_enable_privacy)
        self.btn_pub = ttk.Button(mb, text="Set Public (bdaddr)", command=self.mac_set_public_bdaddr)
        self.btn_gen.grid(row=0, column=0, sticky="ew"); self.btn_static.grid(row=0, column=1, sticky="ew")
        self.btn_priv.grid(row=1, column=0, sticky="ew"); self.btn_pub.grid(row=1, column=1, sticky="ew")
        mb.columnconfigure(0, weight=1); mb.columnconfigure(1, weight=1)

        if IS_WINDOWS:
            # Windows doesn’t expose BD_ADDR changes via public APIs.
            for b in (self.btn_static, self.btn_priv, self.btn_pub):
                b.state(["disabled"])
            ttk.Label(macf, text="Windows note: Adapter MAC/privacy is OS-managed; changing BD_ADDR is not exposed.",
                      foreground="orange").grid(row=3, column=0, columnspan=2, sticky="w")

    # -----------------------------
    # BLE setup / asyncio
    # -----------------------------
    def setup_ble(self):
        self.start_event_loop()

    def start_event_loop(self):
        def run_loop():
            if IS_WINDOWS:
                # Keeps Bleak + Tk happy on Windows
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.run_forever()
        self.thread = threading.Thread(target=run_loop, daemon=True)
        self.thread.start()
        time.sleep(0.1)

    def run_async(self, coro):
        if self.loop:
            return asyncio.run_coroutine_threadsafe(coro, self.loop)
        return None

    # -----------------------------
    # Logging
    # -----------------------------
    def log_message(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        entry = f"[{timestamp}] {message}\n"
        self.root.after(0, lambda: self._update_log(entry))

    def _update_log(self, text):
        self.log_text.insert(tk.END, text)
        self.log_text.see(tk.END)

    # -----------------------------
    # Scanner / Connect
    # -----------------------------
    def toggle_scan(self):
        if not self.is_scanning:
            self.start_scan()
        else:
            self.stop_scan()

    def start_scan(self):
        self.run_async(self._start_scan_async())

    async def _start_scan_async(self):
        try:
            self.is_scanning = True
            self.root.after(0, lambda: self.scan_button.config(text="Stop Scan"))
            self.root.after(0, lambda: self.device_listbox.delete(0, tk.END))
            self.devices.clear()
            self.log_message("Started BLE scanning...")

            def device_found(device: BLEDevice, advertisement_data):
                if device.address not in self.devices:
                    self.devices[device.address] = device
                    device_info = f"{device.name or 'Unknown'} ({device.address}) RSSI: {advertisement_data.rssi}dBm"
                    self.root.after(0, lambda: self.device_listbox.insert(tk.END, device_info))
                    self.log_message(f"Discovered: {device_info}")

            self.scanner = BleakScanner(device_found)
            await self.scanner.start()
            await asyncio.sleep(30)
            await self.scanner.stop()
            self.is_scanning = False
            self.root.after(0, lambda: self.scan_button.config(text="Start Scan"))
            self.log_message("Scan completed.")
        except Exception as e:
            self.log_message(f"Scan error: {e}")
            self.is_scanning = False
            self.root.after(0, lambda: self.scan_button.config(text="Start Scan"))

    def stop_scan(self):
        self.run_async(self._stop_scan_async())

    async def _stop_scan_async(self):
        try:
            if self.scanner:
                await self.scanner.stop()
        finally:
            self.is_scanning = False
            self.root.after(0, lambda: self.scan_button.config(text="Start Scan"))
            self.log_message("Scanning stopped.")

    def connect_device(self):
        selection = self.device_listbox.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Select a device first.")
            return
        idx = selection[0]
        address = list(self.devices.keys())[idx]
        dev = self.devices[address]
        self.run_async(self._connect_device_async(dev))

    async def _connect_device_async(self, device: BLEDevice):
        try:
            self.log_message(f"Connecting to {device.name or device.address}...")
            self.client = BleakClient(device.address)
            await self.client.connect()
            self.connected_device = device
            self.log_message(f"Connected to {device.name or device.address}")
            self.log_message("Discovering services...")
            await self.client.get_services()  # ensure loaded
            services = self.client.services
            self.services.clear()
            self.root.after(0, lambda: self.service_listbox.delete(0, tk.END))
            for svc in services:
                self.services[svc.uuid] = svc
                svc_name = self.get_service_name(svc.uuid)
                info = f"{svc_name} ({svc.uuid})"
                self.root.after(0, lambda i=info: self.service_listbox.insert(tk.END, i))
            self.log_message(f"Discovered {len(services)} services.")
        except Exception as e:
            self.log_message(f"Connection error: {e}")

    def on_service_select(self, _):
        selection = self.service_listbox.curselection()
        if not selection:
            return
        idx = selection[0]
        svc_uuid = list(self.services.keys())[idx]
        svc = self.services[svc_uuid]
        self.run_async(self._get_characteristics_async(svc))

    async def _get_characteristics_async(self, service: BleakGATTService):
        try:
            self.log_message(f"Getting characteristics for {service.uuid}...")
            chars = service.characteristics
            self.characteristics.clear()
            self.root.after(0, lambda: self.char_listbox.delete(0, tk.END))
            for ch in chars:
                self.characteristics[ch.uuid] = ch
                name = self.get_characteristic_name(ch.uuid)
                props = ", ".join(ch.properties)
                info = f"{name} ({ch.uuid}) [{props}]"
                self.root.after(0, lambda i=info: self.char_listbox.insert(tk.END, i))
            self.log_message(f"Found {len(chars)} characteristics.")
        except Exception as e:
            self.log_message(f"Error getting characteristics: {e}")

    def on_characteristic_select(self, _):
        selection = self.char_listbox.curselection()
        if not selection:
            return
        idx = selection[0]
        ch_uuid = list(self.characteristics.keys())[idx]
        self.selected_characteristic = self.characteristics[ch_uuid]
        self.log_message(f"Selected characteristic: {ch_uuid}")

    # -----------------------------
    # Read / Write / Notify
    # -----------------------------
    def parse_data_input(self, data_text: str) -> bytes:
        data_text = data_text.strip()
        if not data_text:
            return b""
        try:
            if "," in data_text:
                parts = [p.strip() for p in data_text.split(",")]
                if any(p.lower().startswith("0x") for p in parts):
                    return bytes(int(p, 16) for p in parts)
                else:
                    return bytes(int(p) & 0xFF for p in parts)
            else:
                return data_text.encode("utf-8")
        except Exception as e:
            raise ValueError(f"Invalid data format: {e}")

    def send_raw_data(self):
        if not self.selected_characteristic:
            messagebox.showwarning("No Selection", "Select a characteristic first.")
            return
        text = self.data_entry.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("No Data", "Enter data to send.")
            return
        self.run_async(self._send_raw_data_async(text))

    async def _send_raw_data_async(self, data_text: str):
        try:
            data = self.parse_data_input(data_text)
            no_resp = "write-without-response" in self.selected_characteristic.properties
            await self.client.write_gatt_char(self.selected_characteristic.uuid, data, response=not no_resp)
            self.log_message(f"Sent {len(data)} bytes -> {self.selected_characteristic.uuid}: " +
                             " ".join(f"{b:02X}" for b in data))
        except Exception as e:
            self.log_message(f"Send error: {e}")

    def read_characteristic(self):
        if not self.selected_characteristic:
            messagebox.showwarning("No Selection", "Select a characteristic first.")
            return
        self.run_async(self._read_characteristic_async())

    async def _read_characteristic_async(self):
        try:
            data = await self.client.read_gatt_char(self.selected_characteristic.uuid)
            hex_s = " ".join(f"{b:02X}" for b in data)
            txt_s = data.decode("utf-8", errors="replace")
            self.log_message(f"Read {len(data)} bytes\n  Hex: {hex_s}\n  Text: {txt_s}")
        except Exception as e:
            self.log_message(f"Read error: {e}")

    def enable_notifications(self):
        if not self.selected_characteristic:
            messagebox.showwarning("No Selection", "Select a characteristic first.")
            return
        self.run_async(self._enable_notifications_async())

    async def _enable_notifications_async(self):
        try:
            def cb(_sender, data: bytearray):
                hex_s = " ".join(f"{b:02X}" for b in data)
                txt_s = data.decode("utf-8", errors="replace")
                self.log_message(f"Notification ({len(data)} bytes)\n  Hex: {hex_s}\n  Text: {txt_s}")
            await self.client.start_notify(self.selected_characteristic.uuid, cb)
            self.log_message("Notifications enabled.")
        except Exception as e:
            self.log_message(f"Notify error: {e}")

    # -----------------------------
    # Fuzzer / Spammer
    # -----------------------------
    def start_fuzzer(self):
        if not self.client or not self.client.is_connected or not self.selected_characteristic:
            messagebox.showwarning("Not Ready", "Connect and select a writable characteristic.")
            return
        if self.fuzz_running:
            return
        pattern = self.fuzz_pattern.get()
        try:
            min_len = int(self.fuzz_min.get()); max_len = int(self.fuzz_max.get())
            rate = max(1, int(self.fuzz_rate.get()))
            limit = int(self.fuzz_limit_iters.get())
        except ValueError:
            messagebox.showerror("Bad Input", "Check fuzz parameters.")
            return
        if min_len < 0 or max_len < 1 or max_len < min_len:
            messagebox.showerror("Bad Lengths", "Min/Max lengths are invalid.")
            return
        self.fuzz_running = True
        write_wo_resp = self.fuzz_write_no_resp.get()
        self.log_message(f"Fuzzer starting: {pattern}, len {min_len}-{max_len}, {rate} pkt/s, max {limit}, " +
                         ("no-response" if write_wo_resp else "with-response"))
        self.fuzz_task = self.run_async(self._fuzz_worker(pattern, min_len, max_len, rate, limit, write_wo_resp))

    def stop_fuzzer(self):
        self.fuzz_running = False
        self.log_message("Fuzzer stop requested.")

    async def _fuzz_worker(self, pattern: str, min_len: int, max_len: int, rate: int, limit: int, no_resp: bool):
        max_payload = 20  # conservative default; raise if you negotiate a bigger MTU
        sent = 0
        delay = 1.0 / float(rate)
        uuid = self.selected_characteristic.uuid

        def make_payload(n: int, i: int) -> bytes:
            n = max(0, min(n, max_payload))
            if pattern == "zeros":
                return bytes([0x00] * n)
            if pattern == "ones":
                return bytes([0xFF] * n)
            if pattern == "increment":
                return bytes((j % 256 for j in range(i, i+n)))
            if pattern == "walking-bit":
                out = bytearray(n); bit = (i % (n*8)) if n>0 else 0
                if n>0: out[bit // 8] = 1 << (bit % 8)
                return bytes(out)
            return bytes(random.getrandbits(8) for _ in range(n))

        try:
            i = 0
            while self.fuzz_running and sent < limit:
                for L in range(min_len, max_len + 1):
                    if not self.fuzz_running or sent >= limit:
                        break
                    payload = make_payload(L, i)
                    try:
                        await self.client.write_gatt_char(uuid, payload, response=not no_resp)
                        sent += 1
                        if sent % max(1, rate) == 0:
                            self.log_message(f"Fuzz sent={sent} last_len={len(payload)}")
                    except Exception as e:
                        self.log_message(f"Fuzz write error at #{sent}: {e}")
                    i += 1
                    await asyncio.sleep(delay)
            self.log_message(f"Fuzzer done. Total sent={sent}.")
        finally:
            self.fuzz_running = False

    # -----------------------------
    # Sniffer (Linux: btmon | Windows: advertisements)
    # -----------------------------
    def start_sniffer(self):
        path = os.path.expanduser(self.sniff_path.get().strip() or "~/ble_radar/sniff.log")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if IS_LINUX:
            if self.sniffer_proc:
                self.log_message("Sniffer already running.")
                return
            iface = getattr(self, "sniff_iface", None)
            iface = iface.get().strip() if iface else "hci0"
            if not which("btmon"):
                messagebox.showerror("btmon not found", "Install BlueZ tools (btmon).")
                return
            self.sniffer_stop.clear()
            self.log_message(f"Starting btmon on {iface} -> {path}")
            try:
                f = open(path, "a", buffering=1, encoding="utf-8", errors="ignore")
                self.sniffer_proc = subprocess.Popen(
                    ["btmon", "-i", iface],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
                )
                def _reader():
                    assert self.sniffer_proc and self.sniffer_proc.stdout
                    for line in self.sniffer_proc.stdout:
                        if self.sniffer_stop.is_set():
                            break
                        f.write(line)
                        if ("LE Advertising" in line) or ("LE Extended" in line) or ("Address:" in line) or ("RSSI:" in line):
                            self.log_message(line.rstrip())
                    f.flush(); f.close()
                self.sniffer_thread = threading.Thread(target=_reader, daemon=True)
                self.sniffer_thread.start()
            except Exception as e:
                self.log_message(f"Sniffer error: {e}")
                self.sniffer_proc = None
        else:
            # Windows soft sniffer: BleakScanner streaming advertisements to file/UI
            if self.sniff_scanner:
                self.log_message("Sniffer already running.")
                return
            self.log_message(f"Starting advertisement sniffer -> {path}")
            self.sniff_task = self.run_async(self._start_soft_sniffer_async(path))

    async def _start_soft_sniffer_async(self, path: str):
        # Close any active scanner to avoid collisions
        try:
            if self.scanner:
                await self.scanner.stop()
                self.is_scanning = False
                self.root.after(0, lambda: self.scan_button.config(text="Start Scan"))
        except Exception:
            pass

        f = open(path, "a", buffering=1, encoding="utf-8", errors="ignore")

        def cb(d: BLEDevice, ad):
            ts = datetime.now().strftime("%H:%M:%S")
            mfg = getattr(ad, "manufacturer_data", None)
            svc = getattr(ad, "service_data", None)
            line = f"[{ts}] ADV {d.address} RSSI={ad.rssi} Name={d.name or d.address} " \
                   f"MFG={dict(mfg) if mfg else {}} SVC_DATA={ {k: v.hex() for k,v in (svc or {}).items()} }"
            f.write(line + "\n")
            # echo interesting bits in UI
            self.log_message(f"ADV {d.address} rssi={ad.rssi} name={d.name or ''}")

        self.sniff_scanner = BleakScanner(cb)
        try:
            await self.sniff_scanner.start()
        except Exception as e:
            self.log_message(f"Soft sniffer error: {e}")
            self.sniff_scanner = None
            f.close()

    def stop_sniffer(self):
        if IS_LINUX:
            self.sniffer_stop.set()
            if self.sniffer_proc:
                try:
                    self.sniffer_proc.terminate()
                except Exception:
                    pass
            self.sniffer_proc = None
            self.log_message("Sniffer stopped.")
        else:
            if self.sniff_scanner:
                self.run_async(self.sniff_scanner.stop())
                self.sniff_scanner = None
            self.log_message("Soft sniffer stopped.")

    # -----------------------------
    # MAC tools (Linux only)
    # -----------------------------
    def mac_set_static(self):
        if IS_WINDOWS:
            messagebox.showinfo("Unsupported on Windows", "Windows manages BLE privacy/MAC at OS level.")
            return
        iface = self.mac_iface.get().strip()
        mac = self.mac_value.get().strip().upper()
        if not iface or not is_valid_mac(mac):
            messagebox.showerror("Bad MAC", "Enter a valid MAC like AA:BB:CC:DD:EE:FF.")
            return
        idx = iface_to_index(iface)
        if not idx:
            messagebox.showerror("Bad Interface", "Use hciX (e.g., hci0).")
            return
        if not which("btmgmt"):
            messagebox.showerror("btmgmt not found", "Install BlueZ (btmgmt).")
            return
        cmds = [
            f"btmgmt --index {idx} power off",
            f"btmgmt --index {idx} static-addr {mac}",
            f"btmgmt --index {idx} power on",
            f"btmgmt --index {idx} le on",
        ]
        self._run_cmds(cmds, "Set static random address")

    def mac_enable_privacy(self):
        if IS_WINDOWS:
            messagebox.showinfo("Unsupported on Windows", "Windows privacy is controlled by the OS; not app-settable.")
            return
        iface = self.mac_iface.get().strip()
        idx = iface_to_index(iface)
        if not idx or not which("btmgmt"):
            messagebox.showerror("Missing", "Need valid hciX and btmgmt.")
            return
        cmds = [
            f"btmgmt --index {idx} power on",
            f"btmgmt --index {idx} le on",
            f"btmgmt --index {idx} privacy on",
        ]
        self._run_cmds(cmds, "Enable LE privacy (resolvable random)")

    def mac_set_public_bdaddr(self):
        if IS_WINDOWS:
            messagebox.showinfo("Unsupported on Windows", "Changing public BD_ADDR isn’t exposed on Windows.")
            return
        iface = self.mac_iface.get().strip()
        mac = self.mac_value.get().strip().upper()
        if not iface or not is_valid_mac(mac):
            messagebox.showerror("Bad MAC", "Enter a valid MAC like AA:BB:CC:DD:EE:FF.")
            return
        if not which("bdaddr"):
            messagebox.showerror("bdaddr not found", "Install bdaddr tool (or use static-addr via btmgmt).")
            return
        cmds = [
            f"hciconfig {iface} down",
            f"bdaddr -i {iface} {mac}",
            f"hciconfig {iface} up",
        ]
        self._run_cmds(cmds, "Set public BD_ADDR (requires adapter support)")

    def _run_cmds(self, cmds: List[str], title: str):
        self.log_message(f"{title} — running {len(cmds)} commands…")
        for c in cmds:
            try:
                self.log_message(f"  $ {c}")
                r = subprocess.run(shlex.split(c), capture_output=True, text=True)
                if r.stdout.strip():
                    self.log_message("    " + r.stdout.strip().replace("\n","\n    "))
                if r.stderr.strip():
                    self.log_message("    [stderr] " + r.stderr.strip().replace("\n","\n    "))
            except Exception as e:
                self.log_message(f"  cmd error: {e}")

    # -----------------------------
    # Disconnect / Close
    # -----------------------------
    def disconnect_device(self):
        if self.client and self.client.is_connected:
            self.run_async(self._disconnect_device_async())
        else:
            self.log_message("No device connected.")

    async def _disconnect_device_async(self):
        try:
            await self.client.disconnect()
            self.log_message("Disconnected.")
        except Exception as e:
            self.log_message(f"Disconnect error: {e}")
        finally:
            self.connected_device = None
            self.client = None

    def clear_log(self):
        self.log_text.delete("1.0", tk.END)

    def get_service_name(self, uuid):
        known_services = {
            "0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
            "0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
            "00001800-0000-1000-8000-00805f9b34fb": "Generic Access",
            "00001801-0000-1000-8000-00805f9b34fb": "Generic Attribute"
        }
        return known_services.get(str(uuid).lower(), "Unknown Service")

    def get_characteristic_name(self, uuid):
        known_chars = {
            "00002a19-0000-1000-8000-00805f9b34fb": "Battery Level",
            "00002a29-0000-1000-8000-00805f9b34fb": "Manufacturer Name",
            "00002a24-0000-1000-8000-00805f9b34fb": "Model Number"
        }
        return known_chars.get(str(uuid).lower(), "Unknown Characteristic")

    def on_closing(self):
        try:
            self.stop_fuzzer()
            self.stop_sniffer()
            if self.client and self.client.is_connected:
                self.run_async(self.client.disconnect())
            if self.loop:
                self.loop.call_soon_threadsafe(self.loop.stop)
        finally:
            self.root.destroy()

# -----------------------------
# Main
# -----------------------------
def main():
    root = tk.Tk()
    app = BLEApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()
