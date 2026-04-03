"""
exif_forensics.py — ARGOS plugin
Metadata extraction and forensics using ExifTool.
Extracts GPS, author, timestamps, camera model, software, hidden data from any file.
https://github.com/exiftool/exiftool
"""

import subprocess
import json
import os
import re
import shutil
import glob
from datetime import datetime

MANIFEST = {
    "id": "exif_forensics",
    "name": "EXIF Forensics",
    "version": "1.0.0",
    "description": "ExifTool: metadata from 200+ file types — GPS, author, timestamps, hidden data",
    "author": "ARGOS",
    "category": "forensics",
    "tools": [
        "exif_extract",
        "exif_gps_hunt",
        "exif_author_hunt",
        "exif_scan_dir",
        "exif_steganography_hints",
    ],
}

RESULTS_DIR = "/opt/argos/logs/exif"
os.makedirs(RESULTS_DIR, exist_ok=True)


def _run(cmd: list, timeout: int = 60) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Timed out after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"Not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def _ensure_exiftool() -> tuple[bool, str]:
    if shutil.which("exiftool"):
        return True, shutil.which("exiftool")
    # Try apt install
    rc, _, _ = _run(["apt-get", "install", "-y", "-qq", "libimage-exiftool-perl"])
    if rc == 0 and shutil.which("exiftool"):
        return True, shutil.which("exiftool")
    return False, "ExifTool not found. Install: apt install libimage-exiftool-perl"


def _parse_exif_json(raw: str) -> list[dict]:
    try:
        data = json.loads(raw)
        return data if isinstance(data, list) else [data]
    except Exception:
        return []


def exif_extract(file_path: str, fields: list = None, all_fields: bool = False) -> dict:
    """
    Extract all metadata from a file using ExifTool.
    Works on images (JPEG/PNG/RAW), PDFs, Office documents, audio/video, and 200+ more formats.

    Args:
        file_path: Path to file (or URL for remote files)
        fields: Specific fields to extract (e.g. ['GPS*', 'Author', 'CreateDate'])
        all_fields: Extract all available fields including binary/hex data (default: False)

    Returns:
        All metadata fields with values, including hidden/embedded data
    """
    if not os.path.exists(file_path) and not file_path.startswith("http"):
        return {"error": f"File not found: {file_path}"}

    ok, exiftool = _ensure_exiftool()
    if not ok:
        return {"error": exiftool}

    cmd = [exiftool, "-json", "-n"]  # -n = numeric values
    if fields:
        for f in fields:
            cmd.append(f"-{f}")
    elif all_fields:
        cmd.append("-all")

    cmd.append(file_path)

    rc, out, err = _run(cmd, timeout=30)
    data = _parse_exif_json(out)

    if not data:
        return {"error": "No metadata extracted", "stderr": err[:500], "file": file_path}

    meta = data[0]

    # Highlight interesting security fields
    security_fields = {
        "gps": {k: v for k, v in meta.items() if "gps" in k.lower()},
        "author": {k: v for k, v in meta.items()
                   if any(f in k.lower() for f in ["author", "creator", "artist", "copyright"])},
        "software": {k: v for k, v in meta.items()
                     if any(f in k.lower() for f in ["software", "application", "producer"])},
        "timestamps": {k: v for k, v in meta.items()
                       if any(f in k.lower() for f in ["date", "time", "modify", "create"])},
        "device": {k: v for k, v in meta.items()
                   if any(f in k.lower() for f in ["make", "model", "serial", "device"])},
    }

    return {
        "file": file_path,
        "metadata": meta,
        "security_highlights": {k: v for k, v in security_fields.items() if v},
        "field_count": len(meta),
        "analysis_time": datetime.utcnow().isoformat(),
    }


def exif_gps_hunt(path: str, recursive: bool = True) -> dict:
    """
    Hunt for GPS coordinates in files. Extracts geolocation from images and documents.
    Useful for OSINT — finding where photos were taken, tracking movement patterns.

    Args:
        path: File path or directory to scan
        recursive: Scan subdirectories (default: True)

    Returns:
        All files with GPS data, coordinates, and Google Maps links
    """
    ok, exiftool = _ensure_exiftool()
    if not ok:
        return {"error": exiftool}

    if not os.path.exists(path):
        return {"error": f"Path not found: {path}"}

    cmd = [exiftool, "-json", "-n", "-GPSLatitude", "-GPSLongitude",
           "-GPSAltitude", "-FileName", "-FileType"]
    if recursive and os.path.isdir(path):
        cmd.append("-r")
    cmd.append(path)

    rc, out, err = _run(cmd, timeout=120)
    data = _parse_exif_json(out)

    results = []
    for entry in data:
        lat = entry.get("GPSLatitude")
        lon = entry.get("GPSLongitude")
        if lat is not None and lon is not None:
            try:
                lat_f = float(lat)
                lon_f = float(lon)
                results.append({
                    "file": entry.get("FileName", ""),
                    "file_type": entry.get("FileType", ""),
                    "latitude": lat_f,
                    "longitude": lon_f,
                    "altitude": entry.get("GPSAltitude"),
                    "maps_link": f"https://www.google.com/maps?q={lat_f},{lon_f}",
                    "osm_link": f"https://www.openstreetmap.org/?mlat={lat_f}&mlon={lon_f}&zoom=15",
                })
            except (ValueError, TypeError):
                pass

    return {
        "path": path,
        "files_with_gps": len(results),
        "locations": results,
        "analysis_time": datetime.utcnow().isoformat(),
    }


def exif_author_hunt(path: str, recursive: bool = True) -> dict:
    """
    Extract author/identity information from files for attribution.
    Finds real names, usernames, email addresses, organization names in metadata.
    Useful for OSINT attribution and document origin analysis.

    Args:
        path: File path or directory to scan
        recursive: Scan subdirectories (default: True)

    Returns:
        All found author info with file associations
    """
    ok, exiftool = _ensure_exiftool()
    if not ok:
        return {"error": exiftool}

    if not os.path.exists(path):
        return {"error": f"Path not found: {path}"}

    cmd = [exiftool, "-json",
           "-Author", "-Creator", "-Artist", "-Copyright",
           "-Company", "-LastModifiedBy", "-UserComment",
           "-XPComment", "-Description", "-Subject",
           "-Software", "-Application",
           "-FileName", "-FileType"]
    if recursive and os.path.isdir(path):
        cmd.append("-r")
    cmd.append(path)

    rc, out, err = _run(cmd, timeout=120)
    data = _parse_exif_json(out)

    author_fields = {"Author", "Creator", "Artist", "Copyright", "Company",
                     "LastModifiedBy", "UserComment", "XPComment",
                     "Description", "Subject", "Software", "Application"}

    results = []
    identities = set()

    for entry in data:
        found = {k: v for k, v in entry.items()
                 if k in author_fields and v and str(v).strip()}
        if found:
            results.append({
                "file": entry.get("FileName", ""),
                "file_type": entry.get("FileType", ""),
                "identity_data": found,
            })
            for v in found.values():
                if isinstance(v, str) and len(v) > 1:
                    identities.add(v.strip())

    # Extract email patterns from all values
    emails = set()
    for entry in data:
        for v in entry.values():
            if isinstance(v, str):
                for m in re.finditer(r'[\w\.\-]+@[\w\.\-]+\.\w+', v):
                    emails.add(m.group(0))

    return {
        "path": path,
        "files_with_identity": len(results),
        "unique_identities": list(identities)[:50],
        "emails_found": list(emails),
        "results": results[:100],
        "analysis_time": datetime.utcnow().isoformat(),
    }


def exif_scan_dir(directory: str, extensions: list = None,
                   export_csv: bool = False) -> dict:
    """
    Batch metadata scan of an entire directory.
    Useful for malware triage, digital evidence processing, and document forensics.

    Args:
        directory: Directory to scan
        extensions: File extensions to include (e.g. ['.jpg', '.pdf', '.docx'])
                    Default: all files
        export_csv: Export results to CSV file (default: False)

    Returns:
        Summary statistics, timeline reconstruction, and anomalies found
    """
    if not os.path.isdir(directory):
        return {"error": f"Directory not found: {directory}"}

    ok, exiftool = _ensure_exiftool()
    if not ok:
        return {"error": exiftool}

    cmd = [exiftool, "-json", "-r", "-n",
           "-FileName", "-FileType", "-FileSize",
           "-FileModifyDate", "-CreateDate", "-ModifyDate",
           "-Make", "-Model", "-Software",
           "-Author", "-Creator",
           "-GPSLatitude", "-GPSLongitude"]

    if extensions:
        for ext in extensions:
            cmd.extend(["-ext", ext.lstrip(".")])

    cmd.append(directory)

    rc, out, err = _run(cmd, timeout=300)
    data = _parse_exif_json(out)

    # Statistics
    file_types = {}
    software_versions = {}
    creation_years = {}
    gps_count = 0
    author_count = 0
    anomalies = []

    for entry in data:
        # File type distribution
        ft = entry.get("FileType", "unknown")
        file_types[ft] = file_types.get(ft, 0) + 1

        # Software
        sw = entry.get("Software", "")
        if sw:
            software_versions[sw] = software_versions.get(sw, 0) + 1

        # Timeline
        for date_field in ["CreateDate", "FileModifyDate", "ModifyDate"]:
            date_val = entry.get(date_field, "")
            if date_val and len(str(date_val)) >= 4:
                year = str(date_val)[:4]
                if year.isdigit():
                    creation_years[year] = creation_years.get(year, 0) + 1
                    break

        # GPS
        if entry.get("GPSLatitude") and entry.get("GPSLongitude"):
            gps_count += 1

        # Author
        if any(entry.get(f) for f in ["Author", "Creator"]):
            author_count += 1

        # Anomaly: future timestamp
        create_date = entry.get("CreateDate", "")
        if create_date and str(create_date)[:4].isdigit():
            if int(str(create_date)[:4]) > datetime.utcnow().year:
                anomalies.append({
                    "type": "future_timestamp",
                    "file": entry.get("FileName", ""),
                    "date": str(create_date),
                })

        # Anomaly: embedded GPS in non-media
        if (entry.get("GPSLatitude") and
                ft not in {"JPEG", "PNG", "TIFF", "HEIC", "RAF", "CR2", "NEF"}):
            anomalies.append({
                "type": "unexpected_gps",
                "file": entry.get("FileName", ""),
                "file_type": ft,
            })

    result = {
        "directory": directory,
        "total_files": len(data),
        "statistics": {
            "file_types": dict(sorted(file_types.items(), key=lambda x: x[1], reverse=True)),
            "software_versions": dict(sorted(software_versions.items(),
                                             key=lambda x: x[1], reverse=True)[:20]),
            "creation_years": dict(sorted(creation_years.items())),
            "files_with_gps": gps_count,
            "files_with_author": author_count,
        },
        "anomalies": anomalies[:50],
        "analysis_time": datetime.utcnow().isoformat(),
    }

    # Export CSV
    if export_csv:
        outfile = os.path.join(RESULTS_DIR, f"exif_scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv")
        import csv
        if data:
            keys = list(data[0].keys())
            with open(outfile, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(data)
            result["csv_file"] = outfile

    return result


def exif_steganography_hints(file_path: str) -> dict:
    """
    Check file for steganography indicators and hidden data hints.
    Analyzes EXIF anomalies, oversized fields, thumbnail mismatches, and suspicious comments.

    Args:
        file_path: Path to image or document file

    Returns:
        Suspicion score, indicators found, and recommendations for deeper analysis
    """
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}"}

    ok, exiftool = _ensure_exiftool()
    if not ok:
        return {"error": exiftool}

    # Get full metadata including binary-encoded fields
    rc, out, err = _run(
        [exiftool, "-json", "-a", "-u", "-g",
         "-ThumbnailImage", "-PreviewImage",
         "-UserComment", "-MakerNote",
         "-Comment", "-XPComment",
         "-Description", "-ImageDescription",
         file_path],
        timeout=30,
    )

    data = _parse_exif_json(out)
    meta = data[0] if data else {}

    indicators = []
    suspicion_score = 0

    # Check for unusual comment fields
    comment_fields = ["UserComment", "Comment", "XPComment", "ImageDescription",
                      "Description", "MakerNote"]
    for field in comment_fields:
        val = meta.get(field, "")
        if val and len(str(val)) > 100:
            indicators.append({
                "indicator": f"Long {field} field ({len(str(val))} chars)",
                "severity": "medium",
                "value_preview": str(val)[:200],
            })
            suspicion_score += 2

    # Check file size vs expected for image type
    rc2, out2, _ = _run(
        [exiftool, "-json", "-FileSize#", "-ImageSize", "-Compression",
         "-ThumbnailLength#", file_path],
        timeout=10,
    )
    size_data = _parse_exif_json(out2)
    if size_data:
        sd = size_data[0]
        file_size = sd.get("FileSize", 0)
        thumb_len = sd.get("ThumbnailLength", 0)

        if isinstance(thumb_len, (int, float)) and isinstance(file_size, (int, float)):
            if thumb_len > file_size * 0.5:
                indicators.append({
                    "indicator": "Oversized thumbnail (possible data hiding)",
                    "severity": "high",
                    "thumbnail_size": thumb_len,
                    "file_size": file_size,
                })
                suspicion_score += 5

    # Check for base64-encoded strings in comments
    for field in comment_fields:
        val = str(meta.get(field, ""))
        import base64 as _b64
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{50,}={0,2}')
        for match in b64_pattern.finditer(val):
            try:
                decoded = _b64.b64decode(match.group(0))
                if len(decoded) > 20:
                    indicators.append({
                        "indicator": f"Base64-encoded data in {field}",
                        "severity": "high",
                        "decoded_preview": decoded[:50].hex(),
                    })
                    suspicion_score += 4
            except Exception:
                pass

    # Run strings on file for hidden text
    rc3, strings_out, _ = _run(["strings", "-n", "8", file_path], timeout=10)
    if rc3 == 0:
        suspicious_strings = []
        for line in strings_out.splitlines():
            # URLs in images
            if re.match(r'https?://', line):
                suspicious_strings.append({"type": "url", "value": line})
                suspicion_score += 1
            # Email addresses
            elif re.search(r'[\w\.]+@[\w\.]+\.\w+', line):
                suspicious_strings.append({"type": "email",
                                            "value": re.search(r'[\w\.]+@[\w\.]+\.\w+', line).group(0)})
        if suspicious_strings:
            indicators.append({
                "indicator": "Suspicious strings found in file",
                "severity": "medium",
                "strings": suspicious_strings[:10],
            })
            suspicion_score += len(suspicious_strings)

    # Overall assessment
    assessment = "clean"
    if suspicion_score >= 10:
        assessment = "HIGH_SUSPICION — manual steganography analysis recommended"
    elif suspicion_score >= 5:
        assessment = "MEDIUM_SUSPICION — review indicators carefully"
    elif suspicion_score >= 2:
        assessment = "LOW_SUSPICION — some unusual metadata"

    return {
        "file": file_path,
        "suspicion_score": suspicion_score,
        "assessment": assessment,
        "indicators": indicators,
        "total_metadata_fields": len(meta),
        "analysis_time": datetime.utcnow().isoformat(),
        "deeper_analysis": [
            "steghide detect -sf " + file_path,
            "binwalk " + file_path,
            "zsteg " + file_path + "  (PNG only)",
        ] if suspicion_score >= 5 else [],
    }


TOOLS = {
    "exif_extract": exif_extract,
    "exif_gps_hunt": exif_gps_hunt,
    "exif_author_hunt": exif_author_hunt,
    "exif_scan_dir": exif_scan_dir,
    "exif_steganography_hints": exif_steganography_hints,
}
