# Detection Rules

GTH is a passive WIDS. It sends no attack frames.

| Rule | Default condition |
|---|---|
| Deauth / Disassoc | 20 Deauth/Disassoc frames in 10 s. 5 sequences or 4 time bins. |
| Probe Recon | 30 Probe Requests and 10 named SSIDs in 30 s. Recon only. |
| Evil Twin signs | 3 beacons in 30 s. saved SSID, new BSSID, weaker security. |
| KARMA signs | 5 matching SSIDs and 2 clients in 60 s. reply delay <= 2 s. |
| Auth rejects | 8 authentication rejects in 60 s. |
| Assoc rejects | 8 association rejects in 60 s. |
| EAPOL attempts | 8 distinct M2 nonces in 60 s. no linked M2/M3/M4 exchange. |
| WPS rejects | 8 WPS NACK errors in 60 s. |
| AP policy change | 3 distinct beacon sequences in 30 s. saved AP name, security, or PMF policy differs. Policy observation only. |

Edit config/default.json to set a trusted AP policy.
The default trusted_aps list is empty.
Use checked ssid, bssid, and security values.
Security values are open, wep, wpa, wpa2, and wpa3.
Use pmf_required only when the AP policy is known.
Use ssid_hex for an exact SSID byte value when needed.
Do not publish a private AP policy.

The Engine rejects bad fields, bad FCS, and old frame order.
Retry copies do not count as new rule input.
Complete verified Proof is needed for a positive attack indicator.
A negative needs enough rule input, time, channel data, and capture quality.
Recon and AP policy change stay observations.
A failed Proof file check overrides a stored unsupported claim.
No confidence percentage is claimed.
