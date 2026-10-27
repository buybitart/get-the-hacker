# Android and Termux

GTH runs in Termux or a supported Linux environment.
The mobile interface is a local browser page. This is not an APK.
Keep app code in the Termux home folder.
Shared storage can block script execution.

Allow shared storage access:

```sh
termux-setup-storage
```

Install Python, Bash, iw, and ip for your system.
Raw capture needs root, a supported kernel, and a USB driver.
Use wlan2 for an external adapter.
A connected interface is not changed automatically.
Managed wlan0 gives link status. It does not give raw WIDS.

```sh
bash install.sh
./gth.sh
```

All Android results use `/sdcard/Download/GTH/session-*`.
Allow storage access before Capture.
An unwritable output folder gives an error.
The app does not hide this error in another output folder.

GPS uses Termux:API when available. Allow location access for GPS.
No GPS fix means no sensor coordinates. Capture keeps running.
Sensor GPS is not a radio source position.
Open the printed local Dashboard URL in your phone browser.
Actual radio and GPS support depend on your phone and driver.
