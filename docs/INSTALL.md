# Installation

Use Linux or Termux with Python 3.11 or newer.
Python must include sqlite3. Bash, iw, and ip are required.
Scapy 2.6.1 is bundled in vendor/. No basic pip setup is needed.

```sh
chmod +x gth.sh install.sh
./gth.sh
```

For a command from any folder:

```sh
bash install.sh
```

The installer creates a launcher in your user bin folder.
It uses ~/.local/bin on Linux and $PREFIX/bin in Termux.
It refuses to overwrite an existing command.
Add the printed bin folder to PATH if needed.
The app can also run with `bash /path/to/gth.sh`.
Paths with spaces are supported.

| Mode | Needs | Result |
|---|---|---|
| Monitor Mode | Root, supported USB adapter, driver, iw, ip | Raw Wi-Fi frames |
| Managed | Working local Wi-Fi link | Link status only |
| No usable adapter | Python and app files | Diagnostic report |
| Replay or Demo | Python and bundled Scapy | Offline analysis |

No usable radio gives NO WIFI INTERFACE or CAPTURE NOT AVAILABLE.
That state saves a report. It does not prove a safe network.

PDF works with the built-in portable writer.
It shows unsupported characters as text escapes.
The full JSON attachment keeps all original characters.
Optional ReportLab can use a local Unicode font.
It is not needed for basic PDF output.
