"""
CTF Atlas — OSINT & Reconnaissance Chapters
"""

chapters = {}

chapters["osint-recon"] = {
    "id": "osint-recon",
    "domain": "osint",
    "category": "Open Source Intelligence (OSINT)",
    "title": "Passive Reconnaissance, MITRE TA0043 Framework & Geospatial Attribution",
    "subtitle": "Certificate Transparency Logs (crt.sh), EXIF GPS Rational Decimal Conversion & Cross-Platform Pivoting",
    "diagram": """+-----------------------------------------------------------------+
|               The OSINT Investigation Pivot Cycle               |
+-----------------------------------------------------------------+
Initial Artifact: User photo 'evidence.jpg'
  |
  +-> 1. EXIF Metadata Extraction (exiftool)
  |     - Camera: Apple iPhone 14 Pro
  |     - Author: 'Agent_Zero_99'
  |     - GPS: 37 deg 48' 36.12" N, 122 deg 25' 14.88" W
  |
  +-> 2. Mathematical Coordinate Conversion:
  |     Decimal Latitude  = 37 + (48/60) + (36.12/3600)  = 37.810033
  |     Decimal Longitude = -(122 + (25/60) + (14.88/3600)) = -122.420800
  |     -> Maps directly to Golden Gate Bridge Vista Point!
  |
  +-> 3. Username Pivoting (Sherlock / WhatsMyName):
        Pivot 'Agent_Zero_99' -> GitHub, Keybase, Reddit profiles!""",
    "theory": """Open Source Intelligence (OSINT) is the collection, correlation, and analysis of publicly available data to generate actionable intelligence. In the MITRE ATT&CK framework, reconnaissance is classified under Tactic TA0043 (Reconnaissance). Passive reconnaissance involves gathering information without directly transmitting packets to the target organization's operational infrastructure, thereby avoiding detection by target SIEMs, firewalls, and intrusion detection systems.

Core OSINT Methodologies & Mathematical Primitives:
1. Public Technical Infrastructure Mining:
   - Certificate Transparency (CT) Logs: RFC 6962 mandates that public Certificate Authorities publish all issued TLS/SSL certificates to append-only public cryptographic audit logs. By querying CT aggregators like `crt.sh`, an investigator enumerates all internal and development subdomains registered by an organization (`%.target.com`) without sending a single DNS query to the target's nameservers.
   - Passive DNS & WHOIS: Services (SecurityTrails, VirusTotal, Shodan, Censys) capture historical DNS resolutions, exposing past IP hosting providers, MX records, and mail servers.
2. Exchangeable Image File Format (EXIF) Internals:
   EXIF (JEITA CP-3451) embeds technical metadata inside JPEG, TIFF, and HEIC image containers using Tag-Length-Value Image File Directories (IFDs).
   - Critical Metadata Tags: Make (0x010F), Model (0x0110), DateTimeOriginal (0x9003), Software (0x0131), and the GPSInfo IFD (0x8825).
   - GPS Rational Serialization: GPS coordinates are stored as three pairs of 32-bit unsigned integers representing Rational numbers (Numerator / Denominator) corresponding to [Degrees, Minutes, Seconds]. The conversion to Decimal Degrees is:
$$\\text{Decimal Degrees} = \\text{Degrees} + \\frac{\\text{Minutes}}{60} + \\frac{\\text{Seconds}}{3600}$$
If the reference tag (`GPSLatitudeRef` or `GPSLongitudeRef`) is 'S' (South) or 'W' (West), the resulting decimal value is multiplied by $-1$.
3. Social & Identity Pivoting:
   Investigating online pseudonyms using tools like `sherlock` across hundreds of social networks. Cross-referencing PGP public key rings, Gravatar hashes (MD5 of email address), and Git commit authorship metadata (`git log --format='%an <%ae>'`).""",
    "commands": [
        {
            "cmd": "exiftool -gps:all -c '%.6f' photo.jpg",
            "why": "Extracts GPS coordinates and formats them directly into decimal degrees with 6 decimal places.",
            "when": "Investigating image files for geolocation attribution.",
            "internals": "Parses EXIF TIFF header IFD structure and performs rational division automatically.",
            "pitfalls": "Many social media platforms (Twitter, Discord, Instagram) automatically strip EXIF data on upload."
        },
        {
            "cmd": "curl -s 'https://crt.sh/?q=%.target.ctf&output=json' | jq -r '.[].name_value' | sort -u",
            "why": "Harvests all known subdomains from public Certificate Transparency logs via crt.sh API.",
            "when": "Initial passive reconnaissance of a corporate domain.",
            "internals": "Queries PostgreSQL database of globally logged X.509 SSL certificates.",
            "pitfalls": "May return expired, retired, or historical subdomains that no longer resolve."
        },
        {
            "cmd": "sherlock target_username --timeout 5",
            "why": "Searches for an identical username across 300+ public websites and social media platforms.",
            "when": "Pivoting from a discovered username to identify additional accounts or code repositories.",
            "internals": "Issues parallel HTTP GET requests checking HTTP status codes (200 vs 404).",
            "pitfalls": "Common usernames (e.g. 'alex', 'admin') will produce high numbers of false positives."
        }
    ],
    "cli_vs_gui": {
        "cli_workflow": "CLI: `exiftool image.jpg | grep -iE 'gps|make|model|date|author|artist'` dumps key attribution data instantly.",
        "gui_workflow": "Google Earth / SunCalc / Overpass Turbo: Geolocation mapping, analyzing shadows to verify time of day, and filtering OpenStreetMap infrastructure features.",
        "speed_tip": "In Google Maps, paste coordinates directly in format `37.810033, -122.420800` to jump straight to the satellite view."
    },
    "triage_workflow": [
        "1. Extract All Metadata: Run `exiftool -a -u -g1 evidence.jpg`.",
        "2. Parse Geolocation: Convert degrees-minutes-seconds to decimal coordinates.",
        "3. Reverse Image Search: Check Google Lens, Yandex Images, and Bing Visual Search.",
        "4. Enumerate Technical Assets: Query `crt.sh`, Shodan, and Wayback Machine.",
        "5. Identity Correlation: Check usernames on GitHub, Reddit, and keybase.io.",
        "6. Timeline Construction: Correlate timestamps across all discovered artifacts."
    ],
    "writeup": {
        "ctf_event": "HackTheBox / SANS Holiday Hack",
        "challenge_name": "Geo-Spy (EXIF & Satellite Attribution)",
        "scenario": "An image 'leak.jpg' was posted by an anonymous whistleblower. Solvers must determine the exact city and landmark where the photograph was taken.",
        "solve_steps": [
            "1. Run exiftool: `exiftool -gps:all -c '%.6f' leak.jpg`.",
            "2. Coordinates extracted: `GPS Latitude: 48.858370 N`, `GPS Longitude: 2.294481 E`.",
            "3. Query decimal coordinates in mapping software: 48.858370, 2.294481.",
            "4. Landmark identified: Champ de Mars, directly beneath the Eiffel Tower in Paris, France.",
            "5. Inspect image comment field: `exiftool -Comment leak.jpg`.",
            "6. Comment contains: `PARIS_EIFFEL_FLAG{EXIF_GPS_DMS_C0NV3RS10N}`.",
            "7. Flag: CTF{EXIF_GPS_DMS_C0NV3RS10N}"
        ],
        "exploit_code": """#!/usr/bin/env python3

def dms_to_decimal(deg, minutes, seconds, ref):
    decimal = deg + (minutes / 60.0) + (seconds / 3600.0)
    if ref in ['S', 'W']:
        decimal = -decimal
    return decimal

lat = dms_to_decimal(48, 51, 30.13, 'N')
lon = dms_to_decimal(2, 17, 40.13, 'E')

print(f"[+] Decimal Latitude: {lat:.6f}")
print(f"[+] Decimal Longitude: {lon:.6f}")
print(f"[+] Google Maps Link: https://maps.google.com/?q={lat:.6f},{lon:.6f}")""",
        "flag": "CTF{EXIF_GPS_DMS_C0NV3RS10N}",
        "mitigation": "Configure mobile devices and organizational photo-upload pipelines to automatically strip GPS location tags (`GPSInfo`) before sharing images publicly."
    }
}
