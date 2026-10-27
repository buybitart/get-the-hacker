"""Read sensor GPS. Never use a sensor fix as a radio-source position."""

from datetime import datetime
import ipaddress
import json
import math
import socket
import subprocess
import time


def _number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("Use a finite number.")
    value = float(value)
    if not math.isfinite(value):
        raise ValueError("Use a finite number.")
    return value


def _timestamp(value):
    if isinstance(value, str):
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError("GPS time needs a time zone.")
        return stamp.timestamp()
    return _number(value)


def _empty(status, reason, provider=None):
    return {
        "status": status, "reason": reason, "lat": None, "lon": None,
        "accuracy_m": None, "timestamp": None, "source": "sensor_gps",
        "provider": provider,
    }


def validate_fix(raw, now=None, max_age_s=5.0, max_accuracy_m=100.0):
    """Check normalized GPS fields. Accuracy is the provider error estimate."""
    try:
        current = _number(time.time() if now is None else now)
        max_age_s = _number(max_age_s)
        max_accuracy_m = _number(max_accuracy_m)
        if max_age_s <= 0 or max_accuracy_m <= 0:
            raise ValueError("GPS limits must be positive.")
        if not isinstance(raw, dict):
            raise ValueError("GPS data must be an object.")
        lat = _number(raw.get("lat"))
        lon = _number(raw.get("lon"))
        accuracy = _number(raw.get("accuracy_m"))
        stamp = _timestamp(raw.get("timestamp"))
        if not -90 <= lat <= 90 or not -180 <= lon <= 180:
            raise ValueError("GPS coordinates are out of range.")
        if accuracy <= 0 or accuracy > max_accuracy_m:
            raise ValueError("GPS error is missing or too high.")
        if raw.get("fix_mode") not in (2, 3):
            raise ValueError("GPS has no valid position fix.")
        if raw.get("mocked") is True or raw.get("simulated") is True:
            raise ValueError("GPS is a simulated fix.")
        if stamp > current + 1.0:
            raise ValueError("GPS time is in the future.")
        if current - stamp > max_age_s:
            raise ValueError("GPS fix is stale.")
        return {
            "status": "valid", "reason": "Sensor position only.",
            "lat": lat, "lon": lon, "accuracy_m": accuracy,
            "timestamp": stamp, "source": "sensor_gps",
            "provider": raw.get("provider"),
            "fix_mode": raw["fix_mode"],
            "accuracy_kind": "provider_error_estimate",
            "age_s": max(0.0, current - stamp),
        }
    except (ValueError, TypeError, OverflowError) as error:
        return _empty("rejected", str(error))


class GPSProvider:
    """Use one bounded GPS read. Poll from a worker to keep capture smooth."""

    def __init__(self, mode="none", host="127.0.0.1", port=2947,
                 timeout_s=0.6, max_age_s=5.0, max_accuracy_m=100.0):
        if mode not in ("none", "gpsd", "termux"):
            raise ValueError("GPS mode must be none, gpsd, or termux.")
        self.mode = mode
        # Numeric addresses avoid an unbounded DNS lookup in a live poll.
        self.host = str(ipaddress.ip_address(host))
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("GPS port is out of range.")
        self.port = port
        self.timeout_s = _number(timeout_s)
        self.max_age_s = _number(max_age_s)
        self.max_accuracy_m = _number(max_accuracy_m)
        if not 0.05 <= self.timeout_s <= 10.0:
            raise ValueError("GPS timeout must be from 0.05 to 10 seconds.")
        if self.max_age_s <= 0 or self.max_accuracy_m <= 0:
            raise ValueError("GPS limits must be positive.")

    def get_fix(self, now=None):
        if self.mode == "none":
            return _empty("unavailable", "GPS is off.", self.mode)
        try:
            if self.mode == "gpsd":
                raw = self._gpsd()
            else:
                raw = self._termux()
            return validate_fix(raw, now=now, max_age_s=self.max_age_s,
                                max_accuracy_m=self.max_accuracy_m)
        except (OSError, ValueError, TypeError, OverflowError,
                subprocess.SubprocessError) as error:
            # Do not print raw process output or provider-controlled text.
            return _empty("unavailable", "GPS read failed: " + type(error).__name__ + ".", self.mode)

    def _gpsd(self):
        deadline = time.monotonic() + self.timeout_s
        data = bytearray()
        total = 0
        with socket.create_connection((self.host, self.port), timeout=self.timeout_s) as sock:
            sock.settimeout(max(0.001, deadline - time.monotonic()))
            sock.sendall(b'?WATCH={"enable":true,"json":true};\n')
            while time.monotonic() < deadline and total < 65536:
                sock.settimeout(max(0.001, deadline - time.monotonic()))
                part = sock.recv(min(4096, 65536 - total))
                if not part:
                    break
                total += len(part)
                data.extend(part)
                while b"\n" in data:
                    line, _, rest = data.partition(b"\n")
                    data = bytearray(rest)
                    try:
                        obj = json.loads(line)
                    except (ValueError, UnicodeDecodeError):
                        continue
                    if not isinstance(obj, dict) or obj.get("class") != "TPV":
                        continue
                    # gpsd may send partial reports. Wait for all required fields.
                    if not all(key in obj for key in ("mode", "time", "lat", "lon")):
                        continue
                    accuracy = obj.get("eph")
                    if accuracy is None and "epx" in obj and "epy" in obj:
                        xerr, yerr = _number(obj["epx"]), _number(obj["epy"])
                        if xerr <= 0 or yerr <= 0:
                            raise ValueError("GPS error must be positive.")
                        accuracy = math.hypot(xerr, yerr)
                    if accuracy is None:
                        continue
                    return {"lat": obj["lat"], "lon": obj["lon"],
                            "accuracy_m": accuracy, "timestamp": obj["time"],
                            "fix_mode": obj["mode"], "simulated": obj.get("status") == 8,
                            "provider": "gpsd"}
        raise ValueError("No full GPS fix.")

    def _termux(self):
        # The last-fix command is bounded. Age is checked before use.
        result = subprocess.run(
            ["termux-location", "-p", "gps", "-r", "last"],
            capture_output=True, text=True, check=True, timeout=self.timeout_s,
        )
        if len(result.stdout) > 16384:
            raise ValueError("GPS reply is too large.")
        obj = json.loads(result.stdout)
        if not isinstance(obj, dict) or obj.get("provider") != "gps":
            raise ValueError("A GPS provider is required.")
        elapsed = _number(obj.get("elapsedMs")) / 1000.0
        if elapsed < 0:
            raise ValueError("GPS age is invalid.")
        return {"lat": obj.get("latitude"), "lon": obj.get("longitude"),
                "accuracy_m": obj.get("accuracy"), "timestamp": time.time() - elapsed,
                "fix_mode": 2, "mocked": obj.get("mocked", False), "provider": "termux"}
