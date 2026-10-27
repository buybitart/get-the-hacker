# Limits

| Area | Limit |
|---|---|
| Identity | A MAC address is not a person ID |
| Silent Recon | A passive receiver sends no required frame |
| Channel | Only the measured channel is checked |
| Payload | Encrypted payload attacks are outside this WIDS scope |
| Loss | Queue loss and delay can hide activity |
| Driver | Driver-level packet loss is not measured |
| AP policy | First-seen APs are not trusted automatically |
| Intent | AP resets and setup errors can match rule patterns |
| Accuracy | Field Accuracy and FP/FN rates are not measured |

Same-security AP clones can escape the baseline downgrade check.
PMF flags do not verify a PMF cryptographic check.
Live mode stores normalized frames. It does not store raw PCAP.
A rule result applies to saved input. It is not whole-city coverage.
NOT DETECTED is not an all-channel safety claim.

Sensor GPS gives the sensor position. It does not locate a sender.
RSSI alone gives no source distance or coordinates.
Source estimates need external calibrated horizontal ranges.
They need at least four checked anchors and valid geometry.
No source range data is created from ordinary Wi-Fi Capture.

Real Android, USB driver, Monitor Mode, and GPS tests need a target device.
Host code tests do not prove those hardware conditions.

## Source range input

The locate command needs external range measurements.
Use one source_id and at least four unique anchor_id values.
Each row needs lat, lon, timestamp, range_m, range_sigma_m,
gps_accuracy_m, method, and calibration_id.
Set method to calibrated_range. Use horizontal ranges only.
Use WGS84 degrees, UTC Unix seconds, and meters.
Range sigma is one standard deviation. It must include real error.
Use one local plane. The supported area is at most 2 km.
Slant ranges and multi-floor sites are not supported.
Range age must be at most 5 seconds.
Measurement time span must be at most 1 second.
A calibration_id is a reference. GTH cannot verify its certificate.
Check source association, clock error, NLOS, and anchor positions.
NLOS means an object blocks the direct radio path.
The model has a 0.5 m error floor. It is not certified.
Host geometry tests do not measure field location Accuracy.
