#!/usr/bin/env python3
"""PRAKASH ADB SECURITY TOOL v3.0
A consent-based Android device management and basic security-audit helper.
Requires Android Platform Tools (adb). Optional screen mirroring requires scrcpy.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

APP_NAME = "PRAKASH ADB SECURITY TOOL"
VERSION = "3.0"
ROOT = Path(__file__).resolve().parent
OUT = ROOT / "output"
OUT.mkdir(exist_ok=True)

def run(cmd, timeout=30, check=False, capture=True):
    try:
        p = subprocess.run(
            cmd, text=True, stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None, timeout=timeout
        )
        if check and p.returncode != 0:
            raise RuntimeError((p.stderr or p.stdout or "Command failed").strip())
        return p
    except FileNotFoundError:
        raise RuntimeError(f"Command not found: {cmd[0]}. Install Android Platform Tools (adb).")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Command timed out after {timeout}s.")

def adb_base(serial=None):
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    return cmd

def require_adb():
    if not shutil.which("adb"):
        print("ERROR: adb not found. Install Android Platform Tools and ensure adb is on PATH.")
        sys.exit(1)

def adb_devices():
    p = run(["adb", "devices", "-l"])
    rows = []
    for line in p.stdout.splitlines()[1:]:
        line = line.strip()
        if not line or line.startswith("*"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            rows.append({"serial": parts[0], "state": parts[1], "details": " ".join(parts[2:])})
    return rows

def choose_device(serial=None, require_online=True):
    devices = adb_devices()
    if serial:
        match = next((d for d in devices if d["serial"] == serial), None)
        if not match:
            raise RuntimeError(f"Device '{serial}' is not listed by adb.")
        if require_online and match["state"] != "device":
            raise RuntimeError(f"Device state is '{match['state']}'. Unlock the phone and approve the USB debugging prompt.")
        return serial
    online = [d for d in devices if d["state"] == "device"]
    if not online:
        if devices:
            print("ADB devices found but none are authorized/online:")
            for d in devices:
                print(f"  {d['serial']}  [{d['state']}] {d['details']}")
        raise RuntimeError("No authorized ADB device found. Connect your own device and approve its debugging prompt.")
    if len(online) == 1:
        return online[0]["serial"]
    print("Available authorized devices:")
    for i, d in enumerate(online, 1):
        print(f"  {i}. {d['serial']}  {d['details']}")
    while True:
        choice = input("Choose device number: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(online):
            return online[int(choice)-1]["serial"]
        print("Enter a valid number.")

def adb(serial, args, timeout=30, check=True):
    p = run(adb_base(serial) + args, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout or "ADB command failed").strip())
    return p.stdout.strip()

def shell(serial, command, timeout=30, check=True):
    return adb(serial, ["shell"] + command, timeout=timeout, check=check)

def safe_name(value):
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in value)[:80] or "device"

def save_text(prefix, content, suffix="txt"):
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = OUT / f"{prefix}_{stamp}.{suffix}"
    path.write_text(content, encoding="utf-8")
    print(f"Saved: {path}")
    return path

def device_info(serial):
    keys = {
        "model": "ro.product.model",
        "manufacturer": "ro.product.manufacturer",
        "brand": "ro.product.brand",
        "device": "ro.product.device",
        "android_release": "ro.build.version.release",
        "sdk": "ro.build.version.sdk",
        "security_patch": "ro.build.version.security_patch",
        "build_fingerprint": "ro.build.fingerprint",
    }
    info = {"serial": serial, "collected_at": datetime.now().isoformat(timespec="seconds")}
    for k, prop in keys.items():
        info[k] = shell(serial, ["getprop", prop], check=False)
    info["battery"] = shell(serial, ["dumpsys", "battery"], check=False)
    info["storage"] = shell(serial, ["df", "-h", "/data"], check=False)
    info["adb_state"] = "authorized/online"
    return info

def print_devices():
    devices = adb_devices()
    if not devices:
        print("No devices listed. Check USB cable, USB debugging, or wireless ADB.")
        return
    for d in devices:
        print(f"{d['serial']:<28} {d['state']:<12} {d['details']}")

def report(serial):
    info = device_info(serial)
    print(json.dumps(info, indent=2, ensure_ascii=False))
    save_text(f"device_report_{safe_name(serial)}", json.dumps(info, indent=2, ensure_ascii=False), "json")

def list_packages(serial, third_party=True):
    args = ["pm", "list", "packages"]
    if third_party:
        args.append("-3")
    result = shell(serial, args, check=False)
    lines = sorted(line.strip() for line in result.splitlines() if line.strip().startswith("package:"))
    print("\n".join(lines) if lines else "(No package results)")
    save_text(f"packages_{safe_name(serial)}", "\n".join(lines))

def audit(serial):
    info = device_info(serial)
    checks = []
    patch = info.get("security_patch", "")
    checks.append({
        "check": "Android security patch",
        "value": patch or "Unknown",
        "status": "REVIEW" if not patch or patch == "0" else "INFO",
        "note": "Compare the patch date with the device vendor's latest supported update."
    })
    adb_enabled = shell(serial, ["settings", "get", "global", "adb_enabled"], check=False)
    checks.append({
        "check": "USB debugging setting",
        "value": adb_enabled or "Unknown",
        "status": "REVIEW" if adb_enabled == "1" else "INFO",
        "note": "Disable USB debugging when it is not needed. ADB authorization still requires user approval."
    })
    dev_options = shell(serial, ["settings", "get", "global", "development_settings_enabled"], check=False)
    checks.append({
        "check": "Developer options",
        "value": dev_options or "Unknown",
        "status": "REVIEW" if dev_options == "1" else "INFO",
        "note": "Review developer options if the phone is not being used for development."
    })
    verified_boot = shell(serial, ["getprop", "ro.boot.verifiedbootstate"], check=False)
    checks.append({
        "check": "Verified boot state (property)",
        "value": verified_boot or "Unavailable",
        "status": "INFO",
        "note": "Property availability and meaning vary by manufacturer; this is not a definitive compromise test."
    })
    report_obj = {
        "tool": APP_NAME, "version": VERSION, "serial": serial,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "device": {k: info.get(k) for k in ("manufacturer", "model", "android_release", "sdk", "security_patch")},
        "checks": checks,
        "limitations": [
            "This is a basic indicator audit, not a full malware scan or certification.",
            "Some Android versions and manufacturers restrict shell access.",
            "No lock-screen, account-protection, authorization, or pairing bypass is performed."
        ]
    }
    print("\nBASIC SECURITY AUDIT")
    for c in checks:
        print(f"- {c['check']}: {c['value']} [{c['status']}] — {c['note']}")
    save_text(f"security_audit_{safe_name(serial)}", json.dumps(report_obj, indent=2), "json")

def take_screenshot(serial):
    remote = "/sdcard/Download/prakash_adb_screenshot.png"
    shell(serial, ["screencap", "-p", remote])
    local = OUT / f"screenshot_{safe_name(serial)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
    adb(serial, ["pull", remote, str(local)])
    shell(serial, ["rm", "-f", remote], check=False)
    print(f"Screenshot saved: {local}")

def screen_record(serial, seconds):
    if seconds < 1 or seconds > 180:
        raise RuntimeError("Recording duration must be 1–180 seconds.")
    remote = "/sdcard/Download/prakash_adb_recording.mp4"
    print(f"Recording for up to {seconds} seconds. Android may show a recording indicator.")
    shell(serial, ["screenrecord", "--time-limit", str(seconds), remote], timeout=seconds + 20)
    local = OUT / f"screenrecord_{safe_name(serial)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.mp4"
    adb(serial, ["pull", remote, str(local)], timeout=60)
    shell(serial, ["rm", "-f", remote], check=False)
    print(f"Recording saved: {local}")

def install_apk(serial, apk):
    path = Path(apk).expanduser().resolve()
    if not path.is_file() or path.suffix.lower() != ".apk":
        raise RuntimeError("Provide a valid local .apk file.")
    print("Only install APKs you trust and have permission to install.")
    if input(f"Install {path.name} on {serial}? Type INSTALL to confirm: ").strip() != "INSTALL":
        print("Cancelled.")
        return
    print(adb(serial, ["install", "-r", str(path)], timeout=180))

def uninstall_package(serial, package):
    if not package or any(c.isspace() for c in package):
        raise RuntimeError("Provide a valid package name, e.g. com.example.app")
    print("Uninstall may remove app data. System apps may not be removable.")
    if input(f"Uninstall {package} from {serial}? Type UNINSTALL to confirm: ").strip() != "UNINSTALL":
        print("Cancelled.")
        return
    print(adb(serial, ["uninstall", package], timeout=90))

def transfer(serial, direction, source, destination):
    if direction == "push":
        local = Path(source).expanduser().resolve()
        if not local.exists():
            raise RuntimeError(f"Local source not found: {local}")
        print(adb(serial, ["push", str(local), destination], timeout=180))
    else:
        local_dest = Path(destination).expanduser().resolve()
        local_dest.parent.mkdir(parents=True, exist_ok=True)
        print(adb(serial, ["pull", source, str(local_dest)], timeout=180))

def reboot_device(serial, mode="normal"):
    if input(f"Reboot device {serial} into {mode} mode? Type REBOOT to confirm: ").strip() != "REBOOT":
        print("Cancelled.")
        return
    if mode == "normal":
        print(adb(serial, ["reboot"], timeout=20))
    elif mode == "recovery":
        print(adb(serial, ["reboot", "recovery"], timeout=20))
    elif mode == "bootloader":
        print(adb(serial, ["reboot", "bootloader"], timeout=20))
    else:
        raise RuntimeError("Unsupported reboot mode.")

def recent_logcat(serial, lines):
    if lines < 1 or lines > 1000:
        raise RuntimeError("Log line count must be 1–1000.")
    print("Log output can contain private app/device information. Review before sharing.")
    if input("Capture recent device logs? Type LOGS to confirm: ").strip() != "LOGS":
        print("Cancelled.")
        return
    output = adb(serial, ["logcat", "-d", "-t", str(lines)], timeout=45, check=False)
    save_text(f"logcat_{safe_name(serial)}", output)

def wireless_pair():
    print("Wireless pairing must be approved on the phone in Developer options > Wireless debugging.")
    host = input("Phone IP: ").strip()
    port = input("Pairing port shown on phone: ").strip()
    if not host or not port.isdigit():
        raise RuntimeError("Enter a valid IP and numeric pairing port.")
    code = input("Pairing code shown on your phone (input hidden is not available): ").strip()
    print(run(["adb", "pair", f"{host}:{port}", code], timeout=45).stdout)

def wireless_connect():
    print("Connect only to a device you own or are authorized to manage.")
    host = input("Phone IP: ").strip()
    port = input("ADB connection port shown on phone: ").strip()
    if not host or not port.isdigit():
        raise RuntimeError("Enter a valid IP and numeric port.")
    print(run(["adb", "connect", f"{host}:{port}"], timeout=30).stdout)

def wireless_disconnect():
    target = input("Device address/serial to disconnect (e.g. 192.168.1.20:37099): ").strip()
    if not target:
        raise RuntimeError("A device address is required.")
    print(run(["adb", "disconnect", target], timeout=20).stdout)

def mirror_screen():
    if not shutil.which("scrcpy"):
        print("scrcpy is not installed. Install scrcpy separately, then run this option again.")
        print("Official project: https://github.com/Genymobile/scrcpy")
        return
    serial = choose_device()
    subprocess.run(["scrcpy", "-s", serial])

def troubleshooter():
    print("\nADB TROUBLESHOOTER")
    print("1. Check devices")
    print("2. Restart ADB server")
    print("3. Show ADB version")
    choice = input("Choose: ").strip()
    if choice == "1":
        print_devices()
    elif choice == "2":
        print(run(["adb", "kill-server"]).stdout)
        print(run(["adb", "start-server"]).stdout)
        print("Reconnect the device and approve the on-phone debugging prompt if requested.")
    elif choice == "3":
        print(run(["adb", "version"]).stdout)
    else:
        print("No action taken.")

def dashboard():
    print(f"\n{APP_NAME} v{VERSION}")
    print("=" * 55)
    print("1. List devices")
    print("2. Device report")
    print("3. Basic security audit")
    print("4. List third-party apps")
    print("5. Take screenshot")
    print("6. Screen recording")
    print("7. Install APK")
    print("8. Uninstall app")
    print("9. Push file to phone")
    print("10. Pull file from phone")
    print("11. Reboot device")
    print("12. Capture recent logcat")
    print("13. Wireless ADB pair")
    print("14. Wireless ADB connect")
    print("15. Wireless ADB disconnect")
    print("16. Screen mirror (scrcpy)")
    print("17. ADB troubleshooter")
    print("0. Exit")
    while True:
        choice = input("\nSelect option: ").strip()
        try:
            if choice == "0":
                print("Goodbye.")
                break
            elif choice == "1":
                print_devices()
            elif choice == "13":
                wireless_pair()
            elif choice == "14":
                wireless_connect()
            elif choice == "15":
                wireless_disconnect()
            elif choice == "16":
                mirror_screen()
            elif choice == "17":
                troubleshooter()
            elif choice in {"2","3","4","5","6","7","8","9","10","11","12"}:
                serial = choose_device()
                if choice == "2": report(serial)
                elif choice == "3": audit(serial)
                elif choice == "4": list_packages(serial)
                elif choice == "5": take_screenshot(serial)
                elif choice == "6":
                    seconds = int(input("Duration seconds (1–180): ").strip())
                    screen_record(serial, seconds)
                elif choice == "7": install_apk(serial, input("Local APK path: ").strip())
                elif choice == "8": uninstall_package(serial, input("Package name: ").strip())
                elif choice == "9": transfer(serial, "push", input("Local file/folder: ").strip(), input("Phone destination path: ").strip())
                elif choice == "10": transfer(serial, "pull", input("Phone source path: ").strip(), input("Local destination path: ").strip())
                elif choice == "11":
                    mode = input("Mode [normal/recovery/bootloader] (normal): ").strip() or "normal"
                    reboot_device(serial, mode)
                elif choice == "12":
                    lines = int(input("How many recent log lines (max 1000): ").strip())
                    recent_logcat(serial, lines)
            else:
                print("Unknown option.")
        except (RuntimeError, ValueError, KeyboardInterrupt) as e:
            print(f"ERROR: {e}")

def main():
    require_adb()
    parser = argparse.ArgumentParser(description=f"{APP_NAME} v{VERSION}")
    parser.add_argument("--serial", help="ADB serial for a specific device")
    parser.add_argument("--list", action="store_true", help="List connected devices")
    parser.add_argument("--report", action="store_true", help="Save device report")
    parser.add_argument("--audit", action="store_true", help="Run basic security audit")
    parser.add_argument("--packages", action="store_true", help="List third-party packages")
    args = parser.parse_args()
    try:
        if args.list:
            print_devices()
            return
        if any((args.report, args.audit, args.packages)):
            serial = choose_device(args.serial)
            if args.report: report(serial)
            if args.audit: audit(serial)
            if args.packages: list_packages(serial)
        else:
            dashboard()
    except (RuntimeError, KeyboardInterrupt) as e:
        print(f"ERROR: {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()
