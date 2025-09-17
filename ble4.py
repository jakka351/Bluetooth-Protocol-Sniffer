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
from typing import Optional, List, Dict

IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")

# -----------------------------
# Windows advertiser (WinRT) + Linux emulator (BlueZ)
# -----------------------------
# Windows advertiser via WinRT
# ===== Windows Advertiser (WinRT / WinSDK) =====
HAS_WINRT = False
if IS_WINDOWS:
    try:
        # Newer package name (Microsoft’s official): winsdk
        from winsdk.windows.devices.bluetooth.advertisement import (
            BluetoothLEAdvertisementPublisher,
            BluetoothLEAdvertisement,
            BluetoothLEAdvertisementDataSection,
            BluetoothLEManufacturerData,
        )
        from winsdk.windows.storage.streams import DataWriter
        HAS_WINRT = True
    except Exception:
        try:
            # Fallback to legacy package name, if someone actually has it
            from winrt.windows.devices.bluetooth.advertisement import (
                BluetoothLEAdvertisementPublisher,
                BluetoothLEAdvertisement,
                BluetoothLEAdvertisementDataSection,
                BluetoothLEManufacturerData,
            )
            from winrt.windows.storage.streams import DataWriter
            HAS_WINRT = True
        except Exception as _e:
            HAS_WINRT = False
            import logging as _logging
            _logging.getLogger("BLEApp").warning("WinRT/Winsdk import failed: %s", _e)

class WindowsAdvertiser:
    """Minimal Windows BLE advertiser using WinRT."""
    def __init__(self, local_name: str, service_uuid: str):
        if not HAS_WINRT:
            raise RuntimeError("winrt not available. Install with: py -m pip install winrt")
        import uuid as _uuid
        self.local_name = local_name
        self.service_uuid = str(_uuid.UUID(service_uuid))  # validate/normalize
        self.publisher: Optional[BluetoothLEAdvertisementPublisher] = None

    def start(self):
        adv = BluetoothLEAdvertisement()
        adv.local_name = self.local_name

        # Put service UUID in a 128-bit Service Data AD section (0x20) for visibility in scanners.
        try:
            import uuid as _uuid
            u = _uuid.UUID(self.service_uuid)
            writer = DataWriter()
            writer.write_bytes(list(u.bytes_le))  # 128-bit UUID little-endian per BLE spec
            writer.write_byte(0x01)              # tiny payload
            section = BluetoothLEAdvertisementDataSection()
            section.data_type = 0x20
            section.data = writer.detach_buffer()
            adv.data_sections.append(section)
        except Exception:
            pass

        # Manufacturer blob so you can spot it easily
        try:
            w2 = DataWriter()
            w2.write_bytes([0xBA, 0xAD, 0xF0, 0x0D])
            adv.manufacturer_data.append(BluetoothLEManufacturerData(0xFFFF, w2.detach_buffer()))
        except Exception:
            pass

        self.publisher = BluetoothLEAdvertisementPublisher(adv)
        self.publisher.start()

    def stop(self):
        if self.publisher:
            try:
                self.publisher.stop()
            except Exception:
                pass
        self.publisher = None


# Linux BlueZ peripheral (advertising + simple GATT server) via dbus-next
if IS_LINUX:
    from dbus_next.aio import MessageBus
    from dbus_next.service import (ServiceInterface, method, dbus_property, PropertyAccess)
    from dbus_next.constants import BusType

    BLUEZ_BUS_NAME = "org.bluez"
    IFACE_OBJECT_MANAGER = "org.freedesktop.DBus.ObjectManager"
    IFACE_ADVERTISING_MANAGER = "org.bluez.LEAdvertisingManager1"
    IFACE_GATT_MANAGER = "org.bluez.GattManager1"
    IFACE_ADVERTISEMENT = "org.bluez.LEAdvertisement1"
    IFACE_GATT_SERVICE = "org.bluez.GattService1"
    IFACE_GATT_CHRC = "org.bluez.GattCharacteristic1"

    async def _find_adapter_path(bus: MessageBus) -> str:
        obj = await bus.get_proxy_object(BLUEZ_BUS_NAME, "/", None)
        mngr = obj.get_interface(IFACE_OBJECT_MANAGER)
        managed = await mngr.call_get_managed_objects()
        for path, ifaces in managed.items():
            if "org.bluez.Adapter1" in ifaces:
                return path
        raise RuntimeError("No Bluetooth adapter found. Is BlueZ running?")

    class LEAdvertisement(ServiceInterface):
        def __init__(self, path: str, local_name: str, service_uuids: List[str]):
            super().__init__(IFACE_ADVERTISEMENT)
            self._path = path
            self.local_name = local_name
            self.service_uuids = service_uuids
            self.include_tx_power = True
            self.type = "peripheral"

        @dbus_property(access=PropertyAccess.READ)
        def Type(self) -> "s":
            return self.type

        @dbus_property(access=PropertyAccess.READ)
        def LocalName(self) -> "s":
            return self.local_name

        @dbus_property(access=PropertyAccess.READ)
        def ServiceUUIDs(self) -> "as":
            return self.service_uuids

        @dbus_property(access=PropertyAccess.READ)
        def IncludeTxPower(self) -> "b":
            return self.include_tx_power

        @method()
        def Release(self):
            pass

        def get_path(self) -> str:
            return self._path

    class GattCharacteristic(ServiceInterface):
        def __init__(self, service, uuid: str, flags: List[str], initial_value: bytes = b""):
            super().__init__(IFACE_GATT_CHRC)
            self.service = service
            self.uuid = uuid
            self.flags = flags
            self.value = bytearray(initial_value)
            self.notifying = False

        @dbus_property(access=PropertyAccess.READ)
        def UUID(self) -> "s":
            return self.uuid

        @dbus_property(access=PropertyAccess.READ)
        def Service(self) -> "o":
            return self.service.get_path()

        @dbus_property(access=PropertyAccess.READ)
        def Flags(self) -> "as":
            return self.flags

        @method()
        def ReadValue(self, options: "a{sv}") -> "ay":
            return bytes(self.value)

        @method()
        def WriteValue(self, value: "ay", options: "a{sv}"):
            self.value = bytearray(value)

        @method()
        async def StartNotify(self):
            if "notify" not in self.flags:
                raise Exception("Notifications not supported")
            self.notifying = True

        @method()
        async def StopNotify(self):
            self.notifying = False

        def get_path(self) -> str:
            return self._path

    class GattService(ServiceInterface):
        def __init__(self, path: str, uuid: str, primary: bool = True):
            super().__init__(IFACE_GATT_SERVICE)
            self._path = path
            self.uuid = uuid
            self.primary = primary

        @dbus_property(access=PropertyAccess.READ)
        def UUID(self) -> "s":
            return self.uuid

        @dbus_property(access=PropertyAccess.READ)
        def Primary(self) -> "b":
            return self.primary

        def get_path(self) -> str:
            return self._path

    class GattApplication(ServiceInterface):
        def __init__(self, path: str):
            super().__init__("org.bluez.GattApplication1")
            self._path = path
            self.services: List[GattService] = []

        def get_path(self) -> str:
            return self._path

        def add_service(self, service: GattService):
            self.services.append(service)

    class LinuxPeripheral:
        """BlueZ advertisement + single-service GATT emulator."""
        def __init__(self, local_name: str = "BLE-Emulator", uuids: Optional[List[str]] = None):
            self.local_name = local_name
            self.uuids = uuids or ["12345678-1234-5678-1234-56789abcdef0"]
            self.bus: Optional[MessageBus] = None
            self.adapter_path: Optional[str] = None
            self.ad_manager = None
            self.gatt_manager = None
            self.advertisement: Optional[LEAdvertisement] = None
            self.gatt_app: Optional[GattApplication] = None
            self.service: Optional[GattService] = None
            self.characteristic: Optional[GattCharacteristic] = None
            self.registered = False
            self.ad_registered = False

        async def start(self):
            self.bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            self.adapter_path = await _find_adapter_path(self.bus)
            obj = await self.bus.get_proxy_object(BLUEZ_BUS_NAME, self.adapter_path, None)
            self.ad_manager = obj.get_interface(IFACE_ADVERTISING_MANAGER)
            self.gatt_manager = obj.get_interface(IFACE_GATT_MANAGER)

            # Build GATT app
            self.gatt_app = GattApplication("/com/example/app")
            self.service = GattService("/com/example/app/service0", self.uuids[0], True)
            char_uuid = "12345678-1234-5678-1234-56789abcdef1"
            self.characteristic = GattCharacteristic(self.service, char_uuid,
                                                     ["read", "write", "notify"], initial_value=b"hello")

            # Export objects
            self.bus.export(self.gatt_app.get_path(), self.gatt_app)
            self.bus.export(self.service.get_path(), self.service)
            self.characteristic._path = self.service.get_path() + "/char0"
            self.bus.export(self.characteristic.get_path(), self.characteristic)
            self.gatt_app.add_service(self.service)

            # Register GATT app
            await self.gatt_manager.call_register_application(self.gatt_app.get_path(), {})
            self.registered = True

            # Register advertisement
            self.advertisement = LEAdvertisement("/com/example/adv0", self.local_name, self.uuids)
            self.bus.export(self.advertisement.get_path(), self.advertisement)
            await self.ad_manager.call_register_advertisement(self.advertisement.get_path(), {})
            self.ad_registered = True

        async def stop(self):
            if not self.bus:
                return
            try:
                if self.ad_registered:
                    await self.ad_manager.call_unregister_advertisement(self.advertisement.get_path())
                    self.ad_registered = False
            except Exception:
                pass
            try:
                if self.registered:
                    await self.gatt_manager.call_unregister_application(self.gatt_app.get_path())
                    self.registered = False
            except Exception:
                pass

        async def notify_tick(self):
            if self.characteristic and self.characteristic.notifying:
                ts = int(time.time()).to_bytes(4, "little")
                self.characteristic.value = bytearray(b"tick:" + ts)

else:
    # Non-Linux stub for the type
    class LinuxPeripheral:
        def __init__(self, local_name: str = "BLE-Emulator", uuids: Optional[List[str]] = None):
            self.local_name = local_name
            self.uuids = uuids or []

        async def start(self): ...
        async def stop(self): ...
        async def notify_tick(self): ...

# -----------------------------
# Logging setup
# -----------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("BLEApp")

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
    b = [random.randint(0, 255) for _ in range(6)]
    b[0] = (b[0] & 0x3F) | 0xC0  # static random: top two bits = 1
    return ":".join(f"{x:02X}" for x in b)

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
        self.devices: Dict[str, BLEDevice] = {}
        self.services: Dict[str, BleakGATTService] = {}
        self.characteristics: Dict[str, BleakGATTCharacteristic] = {}
        self.selected_characteristic: Optional[BleakGATTCharacteristic] = None

        # Async plumbing
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.thread: Optional[threading.Thread] = None

        # Fuzzer state
        self.fuzz_running = False
        self.fuzz_task: Optional[asyncio.Future] = None

        # Broadcast / Emulator state
        self.win_adv: Optional[WindowsAdvertiser] = None       # Windows advertising
        self.peripheral: Optional[LinuxPeripheral] = None      # Linux advertising + GATT
        self.notify_task: Optional[asyncio.Task] = None

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

        # Left panel — Scanner (UNCHANGED)
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

        # Middle panel — Characteristics & IO (UNCHANGED)
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

        # Fuzzer (UNCHANGED)
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

        # Right panel — Log + (REPLACED) Broadcast/Emulator
        right = ttk.LabelFrame(main_frame, text="Communication Log", padding=5)
        right.grid(row=0, column=2, sticky="nsew")
        log_controls = ttk.Frame(right); log_controls.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        ttk.Button(log_controls, text="Clear Log", command=self.clear_log).grid(row=0, column=0, sticky="w")
        self.log_text = scrolledtext.ScrolledText(right, height=30, width=70, bg="black", fg="lime", font=("Courier", 9))
        self.log_text.grid(row=1, column=0, sticky="nsew")
        right.columnconfigure(0, weight=1); right.rowconfigure(1, weight=1)

        # >>> Replacement frame starts here (instead of Sniffer + MAC tools) <<<
        brem = ttk.LabelFrame(right, text=("Broadcast / Emulator (Windows advert, Linux advert+GATT)"), padding=5)
        brem.grid(row=2, column=0, sticky="ew", pady=(6, 4))

        ttk.Label(brem, text="Local Name").grid(row=0, column=0, sticky="w")
        self.emu_localname = ttk.Entry(brem, width=22); self.emu_localname.insert(0, "BLE-Emulator"); self.emu_localname.grid(row=0, column=1, sticky="w")

        ttk.Label(brem, text="Service UUID").grid(row=1, column=0, sticky="w")
        self.emu_uuid = ttk.Entry(brem, width=36); self.emu_uuid.insert(0, "12345678-1234-5678-1234-56789abcdef0"); self.emu_uuid.grid(row=1, column=1, sticky="w")

        brbtn = ttk.Frame(brem); brbtn.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(6,0))
        ttk.Button(brbtn, text="Start Broadcast", command=self.start_broadcast).grid(row=0, column=0, sticky="ew")
        ttk.Button(brbtn, text="Stop Broadcast", command=self.stop_broadcast).grid(row=0, column=1, sticky="ew")
        ttk.Button(brbtn, text=("Start Emulator" if IS_LINUX else "Start Emulator (Linux-only)"), command=self.start_emulator).grid(row=1, column=0, sticky="ew", pady=(4,0))
        ttk.Button(brbtn, text="Stop Emulator", command=self.stop_emulator).grid(row=1, column=1, sticky="ew", pady=(4,0))
        brbtn.columnconfigure(0, weight=1); brbtn.columnconfigure(1, weight=1)

        self.brem_status = tk.StringVar(value=("Windows: advertising supported; GATT emulator requires packaged app" if IS_WINDOWS else "Linux: advertising + GATT emulator available (BlueZ)"))
        ttk.Label(brem, textvariable=self.brem_status, foreground="orange").grid(row=3, column=0, columnspan=2, sticky="w")
        # >>> Replacement frame ends here <<<

    # -----------------------------
    # BLE setup / asyncio
    # -----------------------------
    def setup_ble(self):
        self.start_event_loop()

    def start_event_loop(self):
        def run_loop():
            if IS_WINDOWS:
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
    # Scanner / Connect (UNCHANGED)
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
            await self.client.get_services()
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
    # Read / Write / Notify (UNCHANGED)
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
    # Fuzzer / Spammer (UNCHANGED)
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
        max_payload = 20
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
    # Broadcast / Emulator (NEW)
    # -----------------------------
    def start_broadcast(self):
        name = self.emu_localname.get().strip() or "BLE-Emulator"
        suuid = self.emu_uuid.get().strip() or "12345678-1234-5678-1234-56789abcdef0"

        if IS_WINDOWS:
            try:
                if not HAS_WINRT:
                    raise RuntimeError("WinRT not available. Install with: py -m pip install winrt")
                if not self.win_adv:
                    self.win_adv = WindowsAdvertiser(name, suuid)
                self.win_adv.start()
                self.brem_status.set(f"Windows advertising: ON (name={name})")
                self.log_message(f"Windows advertising started: name={name}, uuid={suuid}")
            except Exception as e:
                self.log_message(f"Windows advertising error: {e}")
                messagebox.showerror("Windows Advertising Error", str(e))
            return

        # Linux path
        if self.peripheral:
            self.log_message("Broadcast already active.")
            return
        self.peripheral = LinuxPeripheral(name, [suuid])
        self.run_async(self._start_peripheral(broadcast_only=True))

    def stop_broadcast(self):
        if IS_WINDOWS:
            if self.win_adv:
                try:
                    self.win_adv.stop()
                except Exception:
                    pass
                self.win_adv = None
                self.brem_status.set("Windows advertising: OFF")
                self.log_message("Windows advertising stopped.")
            return

        self.run_async(self._stop_peripheral())

    def start_emulator(self):
        name = self.emu_localname.get().strip() or "BLE-Emulator"
        suuid = self.emu_uuid.get().strip() or "12345678-1234-5678-1234-56789abcdef0"

        if IS_WINDOWS:
            messagebox.showerror(
                "Not supported in plain Python on Windows",
                "GATT server requires a packaged WinRT app (UWP/WinAppSDK). "
                "This GUI supports advertising on Windows; full emulator is supported on Linux."
            )
            return

        if self.peripheral:
            self.log_message("Emulator already active.")
            return
        self.peripheral = LinuxPeripheral(name, [suuid])
        self.run_async(self._start_peripheral(broadcast_only=False))

    def stop_emulator(self):
        # On Linux it’s the same resource
        self.stop_broadcast()

    async def _start_peripheral(self, broadcast_only: bool):
        try:
            await self.peripheral.start()
            if broadcast_only:
                self.brem_status.set(f"Linux advertising: ON (name={self.peripheral.local_name})")
                self.log_message(f"Broadcast started (Linux): name={self.peripheral.local_name}, uuids={self.peripheral.uuids}")
            else:
                self.brem_status.set(f"Linux emulator: ON (service={self.peripheral.uuids[0]})")
                self.log_message(f"Emulator started (Linux GATT): {self.peripheral.uuids[0]}")
                self.notify_task = asyncio.create_task(self._notify_loop())
        except Exception as e:
            self.log_message(f"Peripheral start failed: {e}")
            self.peripheral = None

    async def _stop_peripheral(self):
        try:
            if self.notify_task:
                self.notify_task.cancel()
                self.notify_task = None
            if self.peripheral:
                await self.peripheral.stop()
            self.log_message("Peripheral stopped.")
        except Exception as e:
            self.log_message(f"Peripheral stop failed: {e}")
        finally:
            self.peripheral = None
            if IS_LINUX:
                self.brem_status.set("Linux advertising/emulator: OFF")

    async def _notify_loop(self):
        try:
            while True:
                await asyncio.sleep(1.0)
                await self.peripheral.notify_tick()
        except asyncio.CancelledError:
            pass

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
            # stop broadcast/emulator if active
            self.stop_emulator()
            self.stop_broadcast()
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
