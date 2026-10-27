"""Select a radio. Keep active Wi-Fi links. Restore only our own changes."""
import json
import re
import subprocess


_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}\Z")
_MAC = r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}"


def _valid_name(name):
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise ValueError("Bad interface name.")
    return name


def _run(args):
    """Run one bounded command. Never use a shell or request root access."""
    try:
        result = subprocess.run(args, capture_output=True, text=True,
                                timeout=4, check=False)
    except FileNotFoundError:
        raise RuntimeError(f"{args[0]} is not installed.") from None
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{args[0]} timed out.") from None
    except OSError as exc:
        raise RuntimeError(f"{args[0]} failed: {exc}.") from None
    if result.returncode:
        detail = " ".join((result.stderr or result.stdout or "Command failed.").split())[:240]
        raise RuntimeError(f"{args[0]} failed: {detail}")
    return result.stdout


def inspect_interface(name):
    """Read interface facts. Unknown link state is None, never disconnected."""
    _valid_name(name)
    state = dict(interface=name, type=None, phy=None, connected=None,
                 ssid=None, bssid=None, frequency_mhz=None, rssi=None,
                 was_up=None, error=None, exists=False)
    errors = []
    try:
        info = _run(["iw", "dev", name, "info"])
        state["exists"] = True
        match = re.search(r"^\s*type\s+(\S+)\s*$", info, re.M)
        if match:
            state["type"] = match.group(1)
        else:
            errors.append("Interface type is not known.")
        match = re.search(r"^\s*wiphy\s+(\d+)\s*$", info, re.M)
        if match:
            state["phy"] = "phy" + match.group(1)
        match = re.search(r"\bchannel\s+\d+\s+\((\d+)\s+MHz\)", info)
        if match:
            state["frequency_mhz"] = int(match.group(1))
    except RuntimeError as exc:
        errors.append(str(exc))
    try:
        link = _run(["iw", "dev", name, "link"])
        match = re.search(r"^\s*Connected to\s+(" + _MAC + r")\b", link, re.M)
        if match:
            state["connected"] = True
            state["bssid"] = match.group(1).lower()
        elif re.search(r"^\s*Not connected\.\s*$", link, re.M):
            state["connected"] = False
        else:
            errors.append("Wi-Fi link state is not known.")
        match = re.search(r"^[ \t]*SSID:[ \t]?(.*)$", link, re.M)
        if match:
            state["ssid"] = match.group(1)[:128]
        match = re.search(r"^\s*freq:\s*(\d+)\s*$", link, re.M)
        if match:
            state["frequency_mhz"] = int(match.group(1))
        match = re.search(r"^\s*signal:\s*(-?\d+(?:\.\d+)?)\s+dBm", link, re.M)
        if match:
            state["rssi"] = float(match.group(1))
    except RuntimeError as exc:
        errors.append(str(exc))
    try:
        links = json.loads(_run(["ip", "-j", "link", "show", "dev", name]))
        entry = next(item for item in links
                     if isinstance(item, dict) and item.get("ifname") == name)
        flags = entry["flags"]
        if not isinstance(flags, list) or not all(isinstance(flag, str) for flag in flags):
            raise ValueError("Bad flags.")
        state["was_up"] = "UP" in flags
    except RuntimeError as exc:
        errors.append(str(exc))
    except (ValueError, TypeError, KeyError, StopIteration):
        errors.append("Interface UP state is not known.")
    state["error"] = " ".join(dict.fromkeys(errors)) or None
    return state


def _supports_monitor(phy):
    if not isinstance(phy, str) or not re.fullmatch(r"phy\d+", phy):
        raise RuntimeError("Radio PHY is not known.")
    info = _run(["iw", "phy", phy, "info"])
    in_modes = False
    for line in info.splitlines():
        value = line.strip()
        if value == "Supported interface modes:":
            in_modes = True
        elif in_modes:
            if not value:
                continue
            if not value.startswith("*"):
                break
            if value[1:].strip() == "monitor":
                return True
    return False


def _check_shared_phy(name, phy):
    """A mode change must not disturb another live interface on this radio."""
    if not isinstance(phy, str) or not re.fullmatch(r"phy\d+", phy):
        raise RuntimeError("Radio PHY is not known.")
    current_phy = None
    peers = []
    for line in _run(["iw", "dev"]).splitlines():
        match = re.fullmatch(r"\s*phy#(\d+)\s*", line)
        if match:
            current_phy = "phy" + match.group(1)
        match = re.fullmatch(r"\s*Interface\s+(\S+)\s*", line)
        if match and current_phy == phy:
            peers.append(match.group(1))
    if name not in peers:
        raise RuntimeError("Shared radio state is not known.")
    for peer in peers:
        if peer == name:
            continue
        try:
            state = inspect_interface(peer)
        except ValueError:
            raise RuntimeError("Shared radio interface name is not supported.") from None
        if state["was_up"] is not False or state["connected"] is True:
            raise RuntimeError(f"{peer} uses the same radio. Link status only.")


class CapturePreparation:
    """Context manager for one radio selection and its rollback state."""

    def __init__(self, state):
        self.state = state

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.restore()
        return False

    def restore(self):
        """Restore the original type and UP state. Return all errors."""
        if not self.state["changed"]:
            return list(self.state.get("restore_errors", []))
        name = self.state["interface"]
        original = self.state["original_state"]
        errors = []
        # Each restore step is tried. A failed step must not hide later errors.
        for command in (["ip", "link", "set", "dev", name, "down"],
                        ["iw", "dev", name, "set", "type", original["type"]],
                        ["ip", "link", "set", "dev", name,
                         "up" if original["was_up"] else "down"]):
            try:
                _run(command)
            except RuntimeError as exc:
                errors.append(str(exc))
        actual = inspect_interface(name)
        restored = (actual["exists"] and actual["type"] == original["type"]
                    and actual["was_up"] == original["was_up"])
        if not restored:
            errors.append("Radio restore check failed.")
        self.state["current_state"] = actual
        self.state["restore_errors"] = errors
        if restored:
            self.state["changed"] = False
        self.state["mode"] = ("managed" if restored and actual["type"] == "managed" else "unavailable")
        return errors


def prepare_capture(preferred=("wlan2", "wlan2mon", "wlan0")):
    """Use Monitor Mode, or return a managed status-only radio.

    Only a disconnected wlan2 may change type. wlan0 and connected links stay
    in their current mode. No scan, channel change, or packet injection is used.
    """
    names = tuple(preferred)
    for name in names:
        _valid_name(name)
    preparation = CapturePreparation(dict(mode="unavailable", interface=None,
                                         original_state=None, changed=False,
                                         reason="No Wi-Fi interface was found.",
                                         restore_errors=[]))
    state = preparation.state
    attempts = []
    managed = []

    def remember(reason):
        state["reason"] = reason
        attempts.append(f"{name}: {reason}")
        if state["mode"] == "managed" and not state["changed"]:
            managed.append(dict(state))

    for name in names:
        original = inspect_interface(name)
        if not original["exists"]:
            attempts.append(f"{name}: {original['error'] or 'Not found.'}")
            continue
        state.update(interface=name, original_state=dict(original), current_state=dict(original),
                     mode="unavailable", changed=False, restore_errors=[])
        if original["type"] == "monitor":
            if original["was_up"] is True:
                state.update(mode="monitor", reason="Monitor Mode is ready.")
                state["attempts"] = attempts
                return preparation
            else:
                remember("Monitor interface is down or its UP state is not known.")
            continue
        if original["type"] != "managed":
            remember("Interface type is not supported.")
            continue
        state["mode"] = "managed"
        if name != "wlan2":
            remember("Managed Mode. Link status only. No frame capture.")
            continue
        if original["connected"] is not False:
            remember("Wi-Fi link is active or its state is not known. Link status only.")
            continue
        if original["was_up"] is None:
            remember("Interface UP state is not known. Link status only.")
            continue
        try:
            if not _supports_monitor(original["phy"]):
                remember("Monitor Mode is not supported. Link status only.")
                continue
            _check_shared_phy(name, original["phy"])
            # Read back before any change. A new active link stops the change.
            before = inspect_interface(name)
            if (before["connected"] is not False or before["type"] != "managed"
                    or before["was_up"] is None or before["phy"] != original["phy"]):
                state["current_state"] = before
                state["mode"] = "managed" if before["type"] == "managed" else "unavailable"
                remember("Radio state changed or is not known. Link status only.")
                continue
            state["original_state"] = dict(before)
            # A command can take effect and then time out. Rollback is needed
            # from the first attempted mutation, not only after its success.
            state["changed"] = True
            _run(["ip", "link", "set", "dev", name, "down"])
            _run(["iw", "dev", name, "set", "type", "monitor"])
            _run(["ip", "link", "set", "dev", name, "up"])
            actual = inspect_interface(name)
            if actual["type"] != "monitor" or actual["was_up"] is not True:
                raise RuntimeError("Monitor Mode check failed.")
            state.update(mode="monitor", reason="Monitor Mode is ready.",
                         current_state=actual, attempts=attempts)
            return preparation
        except RuntimeError as exc:
            errors = preparation.restore()
            if state["changed"]:
                state.update(mode="unavailable", attempts=attempts,
                             reason=f"{exc} Radio restore failed: {' '.join(errors)}")
                return preparation
            remember(f"{exc} Link status only." + (f" Restore warnings: {' '.join(errors)}" if errors else ""))
        except BaseException as exc:
            # The caller cannot restore an object that this function has not
            # returned. Undo partial changes before Ctrl+C or SystemExit exits.
            errors = preparation.restore()
            if errors:
                exc.add_note("Radio restore errors: " + " ".join(errors))
            raise
    if managed:
        # An active managed link gives useful diagnostics when capture is not
        # available. Otherwise keep the configured interface preference.
        selected = next((item for item in managed
                         if item["current_state"]["connected"] is True), managed[0])
        state.update(selected)
    else:
        state.update(mode="unavailable", reason="No usable Wi-Fi interface was found.")
    state["attempts"] = attempts
    if state["mode"] == "unavailable" and attempts:
        state["reason"] += " " + " ".join(attempts)
    return preparation
