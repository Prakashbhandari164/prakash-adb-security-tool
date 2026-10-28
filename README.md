# PRAKASH ADB SECURITY TOOL v3.0

A consent-based Android device management and basic security-audit helper for devices you own or are authorized to manage.

## Features
- Multi-device listing and selection
- Device information report (model, Android release, security patch, battery, storage)
- Basic security indicators (debugging setting, developer options, patch date, verified-boot property)
- Third-party package listing
- Screenshot capture
- Screen recording (Android `screenrecord`, up to 180 seconds)
- Install trusted APKs and uninstall packages with explicit confirmation
- Copy files/folders with ADB push/pull
- Reboot normally, into recovery, or bootloader with confirmation
- Recent logcat export with confirmation
- Wireless ADB pairing/connect/disconnect helpers
- Optional screen mirroring using `scrcpy`
- ADB troubleshooting menu
- JSON and text reports saved to `output/`

## Important safety limits
This tool does **not** bypass screen locks, Google account/FRP protection, ADB authorization, wireless pairing, or other security controls. It does not extract passwords, SMS, contacts, call history, or private app data. Logcat and screenshots may contain private information; review before sharing. Use only with the device owner's permission.

## Requirements
- Python 3.9+
- Android Platform Tools (`adb`) installed and available on PATH
- Android device with USB debugging enabled, or Wireless debugging enabled
- Optional: `scrcpy` installed for screen mirroring

## Termux setup (Android)
On Termux, install the dependencies:
```bash
pkg update
pkg install python android-tools git
```
Download/clone this repository, then:
```bash
cd PRAKASH_ADB_SECURITY_TOOL_V3
python main.py
```
Note: ADB access from Termux to the same Android phone varies by Android version and device. For a separate Android device, connect by USB OTG or use Android Wireless debugging pairing. Follow the prompts shown on the phone; this tool cannot approve pairing on your behalf.

## Linux/macOS/Windows
1. Install Android Platform Tools from Google's official Android developer documentation.
2. Ensure `adb` is on PATH.
3. On the phone, enable Developer options > USB debugging.
4. Connect the phone and approve the RSA debugging prompt on the phone.
5. Run:
```bash
python main.py
```

## Command-line shortcuts
```bash
python main.py --list
python main.py --report
python main.py --audit
python main.py --packages
python main.py --serial YOUR_DEVICE_SERIAL --audit
```

## Screen mirroring
Install `scrcpy` separately from its official project: https://github.com/Genymobile/scrcpy
Then choose menu item 16. This launches scrcpy only for the selected authorized device.

## Output files
Reports and exports are written to `output/`. Keep this folder private if reports contain device identifiers or logs.

## Limitations
- This is a practical starter tool, not a full forensic product or malware scanner.
- Some commands may be restricted by Android version/manufacturer.
- Screen recording support depends on Android build and available storage.
- `adb install` may require approval or be blocked by device policy.
- Security audit findings are indicators only; they are not a definitive pass/fail certification.

## License
MIT — see `LICENSE`.
