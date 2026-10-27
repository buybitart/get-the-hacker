"""Conditional 2D radio-source position from calibrated horizontal ranges.

No RSSI distance model is used. A MAC address is not a person identity.
"""

import math
import time

from .gps import _number, _timestamp


WGS84_A = 6378137.0
WGS84_E2 = 6.6943799901413165e-3
MODEL_MARGIN_M = 0.5
RADIUS_FACTOR = math.sqrt(-2.0 * math.log(0.05))


def _unsupported(reason, **details):
    return {"status": "unsupported", "reason": reason, "lat": None,
            "lon": None, "uncertainty_m": None, **details}


def _ecef(lat, lon):
    latitude, longitude = math.radians(lat), math.radians(lon)
    sine, cosine = math.sin(latitude), math.cos(latitude)
    radius = WGS84_A / math.sqrt(1.0 - WGS84_E2 * sine * sine)
    return (radius * cosine * math.cos(longitude),
            radius * cosine * math.sin(longitude),
            radius * (1.0 - WGS84_E2) * sine)


def _xy(lat, lon, lat0, lon0):
    # Exact ECEF rotation avoids the high-latitude error of a degree grid.
    dx, dy, dz = (v - origin for v, origin in zip(_ecef(lat, lon), _ecef(lat0, lon0)))
    phi, lam = math.radians(lat0), math.radians(lon0)
    east = -math.sin(lam) * dx + math.cos(lam) * dy
    north = (-math.sin(phi) * math.cos(lam) * dx
             -math.sin(phi) * math.sin(lam) * dy + math.cos(phi) * dz)
    return east, north


def _latlon(x, y, lat0, lon0):
    phi, lam = math.radians(lat0), math.radians(lon0)
    ox, oy, oz = _ecef(lat0, lon0)
    # Local up is zero. The model is a plane, not a terrain map.
    ex = ox - math.sin(lam) * x - math.sin(phi) * math.cos(lam) * y
    ey = oy + math.cos(lam) * x - math.sin(phi) * math.sin(lam) * y
    ez = oz + math.cos(phi) * y
    horizontal = math.hypot(ex, ey)
    latitude = math.atan2(ez, horizontal * (1 - WGS84_E2))
    for _ in range(12):
        radius = WGS84_A / math.sqrt(1 - WGS84_E2 * math.sin(latitude) ** 2)
        new_latitude = math.atan2(ez + WGS84_E2 * radius * math.sin(latitude), horizontal)
        if abs(new_latitude - latitude) < 1e-14:
            latitude = new_latitude
            break
        latitude = new_latitude
    return math.degrees(latitude), math.degrees(math.atan2(ey, ex))


def _eigen(a, b, c):
    gap = math.hypot(a - c, 2.0 * b)
    return (a + c - gap) / 2.0, (a + c + gap) / 2.0


def _solve(a, b, c, u, v):
    determinant = a * c - b * b
    if not math.isfinite(determinant) or determinant <= 1e-12 * max(a * c, 1e-300):
        raise ValueError("Range geometry has no stable solution.")
    return ((c * u - b * v) / determinant,
            (a * v - b * u) / determinant)


def _normal(x, y, rows):
    a = b = c = u = v = cost = 0.0
    residuals = []
    for ax, ay, radius, sigma in rows:
        dx, dy = x - ax, y - ay
        distance = math.hypot(dx, dy)
        residual = distance - radius
        jx, jy = (dx / distance, dy / distance) if distance > 1e-12 else (0.0, 0.0)
        weight = 1.0 / (sigma * sigma)
        a += weight * jx * jx
        b += weight * jx * jy
        c += weight * jy * jy
        u += weight * jx * residual
        v += weight * jy * residual
        cost += weight * residual * residual
        residuals.append(residual)
    return a, b, c, u, v, cost, residuals


def _fit(start, rows):
    x, y = start
    for iteration in range(80):
        a, b, c, u, v, cost, _ = _normal(x, y, rows)
        dx, dy = _solve(a, b, c, u, v)
        if math.hypot(dx, dy) < 1e-6:
            return x, y, iteration + 1
        step = 1.0
        accepted = False
        for _ in range(24):
            nx, ny = x - step * dx, y - step * dy
            next_cost = _normal(nx, ny, rows)[5]
            if math.isfinite(next_cost) and next_cost < cost:
                x, y = nx, ny
                accepted = True
                break
            step *= 0.5
        if not accepted:
            if math.hypot(u, v) < 1e-6:
                return x, y, iteration + 1
            raise ValueError("Range solver did not converge.")
        if step * math.hypot(dx, dy) < 1e-6:
            return x, y, iteration + 1
    raise ValueError("Range solver did not converge.")


def estimate_position(measurements, now=None, max_age_s=5.0):
    """Estimate only from four or more fresh calibrated horizontal ranges.

    Input: anchor_id, source_id, lat, lon, timestamp, range_m,
    range_sigma_m, gps_accuracy_m, method, calibration_id.
    Range errors must include calibration, clock, motion, and NLOS error.
    """
    try:
        current = _number(time.time() if now is None else now)
        age_limit = _number(max_age_s)
        if age_limit <= 0:
            raise ValueError("Range age limit must be positive.")
        if not isinstance(measurements, (list, tuple)) or not 4 <= len(measurements) <= 256:
            raise ValueError("Use 4 to 256 independent range anchors.")
        ids, source_ids, rows_in = set(), set(), []
        for item in measurements:
            if not isinstance(item, dict):
                raise ValueError("Each range must be an object.")
            for key in ("anchor_id", "source_id", "calibration_id"):
                if not isinstance(item.get(key), str) or not item[key].strip() or len(item[key]) > 128:
                    raise ValueError("A range ID is missing or invalid.")
            if item["anchor_id"] in ids:
                raise ValueError("Anchor IDs must be unique.")
            ids.add(item["anchor_id"])
            source_ids.add(item["source_id"])
            if item.get("method") != "calibrated_range":
                raise ValueError("Only calibrated measured ranges are supported. RSSI is not a range.")
            if item.get("range_kind", "horizontal") != "horizontal":
                raise ValueError("Use horizontal ranges in the same local plane.")
            lat, lon = _number(item.get("lat")), _number(item.get("lon"))
            if not -85 <= lat <= 85 or not -180 <= lon <= 180:
                raise ValueError("Anchor coordinates are outside the local model.")
            stamp = _timestamp(item.get("timestamp"))
            if stamp > current + 1.0 or current - stamp > age_limit:
                raise ValueError("Range time is stale or in the future.")
            radius = _number(item.get("range_m"))
            range_sigma = _number(item.get("range_sigma_m"))
            gps_error = _number(item.get("gps_accuracy_m"))
            if not 0 < radius <= 2000 or not 0 < range_sigma <= 100 or not 0 <= gps_error <= 100:
                raise ValueError("Range or error is outside the local model.")
            # Use the entire GPS horizontal error as one radial error term.
            sigma = math.hypot(range_sigma, gps_error, MODEL_MARGIN_M)
            rows_in.append((lat, lon, stamp, radius, sigma))
        if len(source_ids) != 1:
            raise ValueError("Ranges must refer to the same radio source.")
        stamps = [row[2] for row in rows_in]
        if max(stamps) - min(stamps) > 1.0:
            raise ValueError("Range time span is over 1 second.")
        lat0, lon0 = rows_in[0][0:2]
        rows = []
        for lat, lon, _, radius, sigma in rows_in:
            x, y = _xy(lat, lon, lat0, lon0)
            if math.hypot(x, y) > 2000:
                raise ValueError("Anchor area is over 2 km.")
            if any(math.hypot(x - row[0], y - row[1]) < 1.0 for row in rows):
                raise ValueError("Anchor positions must be at least 1 m apart.")
            rows.append((x, y, radius, sigma))
        cx = sum(row[0] for row in rows) / len(rows)
        cy = sum(row[1] for row in rows) / len(rows)
        a = sum((row[0] - cx) ** 2 for row in rows)
        b = sum((row[0] - cx) * (row[1] - cy) for row in rows)
        c = sum((row[1] - cy) ** 2 for row in rows)
        low, high = _eigen(a, b, c)
        if low <= 0 or high / low > 100:
            raise ValueError("Anchors are collinear or have poor geometry.")
        # Squared-range differences give a useful start. Final fitting uses
        # the original ranges and weights, not these correlated differences.
        a = b = c = u = v = 0.0
        x0, y0, r0, sigma0 = rows[0]
        for x, y, radius, sigma in rows[1:]:
            jx, jy = 2 * (x - x0), 2 * (y - y0)
            target = x*x + y*y - radius*radius - x0*x0 - y0*y0 + r0*r0
            weight = 1 / (4 * (radius*radius*sigma*sigma + r0*r0*sigma0*sigma0))
            a += weight * jx * jx
            b += weight * jx * jy
            c += weight * jy * jy
            u += weight * jx * target
            v += weight * jy * target
        starts = [(cx, cy), _solve(a, b, c, u, v)]
        candidates = []
        for start in starts:
            try:
                result = _fit(start, rows)
                candidates.append((_normal(result[0], result[1], rows)[5], result))
            except ValueError:
                continue
        if not candidates:
            raise ValueError("Range solver did not converge.")
        _, (x, y, iterations) = min(candidates)
        if not math.isfinite(x) or not math.isfinite(y) or math.hypot(x, y) > 2000:
            raise ValueError("Source position is outside the local model.")
        a, b, c, _, _, cost, residuals = _normal(x, y, rows)
        low, high = _eigen(a, b, c)
        if low <= 0 or high / low > 100:
            raise ValueError("Source range geometry is poor.")
        reduced = cost / (len(rows) - 2)
        max_scaled = max(abs(r) / row[3] for r, row in zip(residuals, rows))
        if reduced > 9 or max_scaled > 4:
            raise ValueError("Range residual is too high. Check NLOS and calibration.")
        uncertainty = RADIUS_FACTOR * math.sqrt(max(1.0, reduced) / low) + MODEL_MARGIN_M
        if uncertainty > 200:
            raise ValueError("Source uncertainty is over 200 m.")
        lat, lon = _latlon(x, y, lat0, lon0)
        return {
            "status": "estimated", "reason": "Conditional radio-source estimate.",
            "source_id": next(iter(source_ids)), "timestamp": max(stamps),
            "lat": lat, "lon": lon, "uncertainty_m": uncertainty,
            "uncertainty_kind": "conditional_95_percent_model_radius",
            "confidence": None, "human_identity": None,
            "anchor_count": len(rows), "time_span_s": max(stamps) - min(stamps),
            "residual_rms_m": math.sqrt(sum(r*r for r in residuals) / len(rows)),
            "reduced_chi_square": reduced, "geometry_condition": high / low,
            "iterations": iterations, "method": "weighted_calibrated_range_2d",
            "calibration_ids": sorted({item["calibration_id"] for item in measurements}),
            "limitations": "Model error is not field accuracy. Source ID can be spoofed.",
        }
    except (ValueError, TypeError, OverflowError, ZeroDivisionError) as error:
        return _unsupported(str(error))


def estimate_movement(estimates, max_gap_s=60.0, max_speed_m_s=80.0):
    """Check the last two source estimates. Do not infer a human identity."""
    try:
        gap_limit, speed_limit = _number(max_gap_s), _number(max_speed_m_s)
        if gap_limit <= 0 or speed_limit <= 0:
            raise ValueError("Movement limits must be positive.")
        if not isinstance(estimates, (list, tuple)) or len(estimates) < 2:
            raise ValueError("Two supported source estimates are required.")
        first, last = estimates[-2:]
        for item in (first, last):
            if not isinstance(item, dict) or item.get("status") != "estimated":
                raise ValueError("Both source estimates must be supported.")
            if item.get("method") != "weighted_calibrated_range_2d":
                raise ValueError("Use supported range estimates only.")
        source = first.get("source_id")
        if not isinstance(source, str) or not source or source != last.get("source_id"):
            raise ValueError("Movement needs the same radio-source ID.")
        start, end = _timestamp(first.get("timestamp")), _timestamp(last.get("timestamp"))
        dt = end - start
        if not 0 < dt <= gap_limit:
            raise ValueError("Source estimates have no valid time order or gap.")
        coords = [(_number(item.get("lat")), _number(item.get("lon"))) for item in (first, last)]
        if any(not -85 <= lat <= 85 or not -180 <= lon <= 180 for lat, lon in coords):
            raise ValueError("Source coordinates are outside the local model.")
        errors = [_number(item.get("uncertainty_m")) for item in (first, last)]
        if any(not 0 < error <= 200 for error in errors):
            raise ValueError("Source uncertainty is invalid.")
        dx, dy = _xy(*coords[1], *coords[0])
        distance = math.hypot(dx, dy)
        error = sum(errors)
        if distance > 2000 or distance / dt > speed_limit:
            raise ValueError("Source jump is outside the movement model.")
        if distance <= error:
            return _unsupported("Movement is below combined uncertainty.",
                                displacement_m=distance, combined_uncertainty_m=error,
                                elapsed_s=dt, source_id=source)
        return {
            "status": "movement_supported", "reason": "Radio-source change exceeds model uncertainty.",
            "source_id": source, "timestamp": end, "displacement_m": distance,
            "uncertainty_m": error, "elapsed_s": dt, "speed_m_s": distance / dt,
            "minimum_speed_m_s": (distance - error) / dt,
            "human_identity": None, "confidence": None,
            "limitations": "Source ID can be spoofed. This does not track a person.",
        }
    except (ValueError, TypeError, OverflowError, ZeroDivisionError) as error:
        return _unsupported(str(error))
