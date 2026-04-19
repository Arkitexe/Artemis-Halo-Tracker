"""
Azure region resolver for Halo Server Radar v12.

Uses the official Microsoft Azure ServiceTags JSON
(https://www.microsoft.com/en-us/download/details.aspx?id=56519) to map any
IPv4 address to its Azure region with proper CIDR matching.

The full ServiceTags data is embedded as a gzipped, base64-encoded blob so
this module is fully self-contained and works inside a PyInstaller .exe.

Public API:
    ip_to_region(ip)       -> (display_name, azure_region_id) or (None, None)
    is_azure_front_door(ip) -> bool  (True = CDN edge, NEVER a game server)
    is_xbox_live_infra(ip)  -> bool  (True = Xbox Live infrastructure)
"""

from __future__ import annotations

import base64
import bisect
import gzip
import ipaddress
import json
from typing import Optional

# ---------------------------------------------------------------------------
# Embedded Azure ServiceTags data (gzipped + base64)
# Source: ServiceTags_Public_<date>.json
#
# Format after decompression:
#   {
#     "azure_regions": [["1.2.3.0/24", "eastus"], ...],   # 10K+ entries
#     "front_door":    ["1.2.3.0/24", ...],               # ~100 entries
#   }
# ---------------------------------------------------------------------------

_AZURE_DATA_B64 = """__AZURE_DATA_B64_PLACEHOLDER__"""

# Display-friendly names for each Azure region.
# This part stays hand-curated because the raw region IDs (eastus2, centralus)
# don't tell a player where they are.
REGION_DISPLAY = {
    "eastus":             ("Virginia, USA",             "East US"),
    "eastus2":            ("Virginia, USA",             "East US 2"),
    "eastus3":            ("Georgia, USA",              "East US 3"),
    "westus":             ("California, USA",           "West US"),
    "westus2":            ("Washington, USA",           "West US 2"),
    "westus3":            ("Arizona, USA",              "West US 3"),
    "centralus":          ("Iowa, USA",                 "Central US"),
    "northcentralus":     ("Illinois, USA",             "North Central US"),
    "southcentralus":     ("Texas, USA",                "South Central US"),
    "westcentralus":      ("Wyoming, USA",              "West Central US"),
    "centraluseuap":      ("Iowa, USA",                 "Central US EUAP"),
    "eastus2euap":        ("Virginia, USA",             "East US 2 EUAP"),
    "canadacentral":      ("Toronto, Canada",           "Canada Central"),
    "canadaeast":         ("Quebec, Canada",            "Canada East"),
    "mexicocentral":      ("Queretaro, Mexico",         "Mexico Central"),
    "brazilsouth":        ("Sao Paulo, Brazil",         "Brazil South"),
    "brazilse":           ("Rio de Janeiro, Brazil",    "Brazil Southeast"),
    "brazilsoutheast":    ("Rio de Janeiro, Brazil",    "Brazil Southeast"),
    "brazilne":           ("Recife, Brazil",            "Brazil Northeast"),
    "northeurope":        ("Dublin, Ireland",           "North Europe"),
    "westeurope":         ("Amsterdam, Netherlands",    "West Europe"),
    "uksouth":            ("London, UK",                "UK South"),
    "ukwest":             ("Cardiff, UK",               "UK West"),
    "francecentral":      ("Paris, France",             "France Central"),
    "francesouth":        ("Marseille, France",         "France South"),
    "germanywestcentral": ("Frankfurt, Germany",        "Germany West Central"),
    "germanynorth":       ("Berlin, Germany",           "Germany North"),
    "swedencentral":      ("Gavle, Sweden",             "Sweden Central"),
    "swedensouth":        ("Malmo, Sweden",             "Sweden South"),
    "switzerlandnorth":   ("Zurich, Switzerland",       "Switzerland North"),
    "switzerlandwest":    ("Geneva, Switzerland",       "Switzerland West"),
    "norwayeast":         ("Oslo, Norway",              "Norway East"),
    "norwaywest":         ("Stavanger, Norway",         "Norway West"),
    "polandcentral":      ("Warsaw, Poland",            "Poland Central"),
    "italynorth":         ("Milan, Italy",              "Italy North"),
    "spaincentral":       ("Madrid, Spain",             "Spain Central"),
    "austriaeast":        ("Vienna, Austria",           "Austria East"),
    "belgiumcentral":     ("Brussels, Belgium",         "Belgium Central"),
    "denmarkeast":        ("Copenhagen, Denmark",       "Denmark East"),
    "finlandcentral":     ("Helsinki, Finland",         "Finland Central"),
    "greececentral":      ("Athens, Greece",            "Greece Central"),
    "eastasia":           ("Hong Kong",                 "East Asia"),
    "southeastasia":      ("Singapore",                 "Southeast Asia"),
    "japaneast":          ("Tokyo, Japan",              "Japan East"),
    "japanwest":          ("Osaka, Japan",              "Japan West"),
    "koreacentral":       ("Seoul, South Korea",        "Korea Central"),
    "koreasouth":         ("Busan, South Korea",        "Korea South"),
    "australiaeast":      ("New South Wales, Australia","Australia East"),
    "australiasoutheast": ("Victoria, Australia",       "Australia Southeast"),
    "australiacentral":   ("Canberra, Australia",       "Australia Central"),
    "australiacentral2":  ("Canberra, Australia",       "Australia Central 2"),
    "newzealandnorth":    ("Auckland, New Zealand",     "New Zealand North"),
    "centralindia":       ("Pune, India",               "Central India"),
    "southindia":         ("Chennai, India",            "South India"),
    "westindia":          ("Mumbai, India",             "West India"),
    "jioindiawest":       ("Jamnagar, India",           "Jio India West"),
    "jioindiacentral":    ("Nagpur, India",             "Jio India Central"),
    "indonesiacentral":   ("Jakarta, Indonesia",        "Indonesia Central"),
    "malaysiawest":       ("Kuala Lumpur, Malaysia",    "Malaysia West"),
    "southafricanorth":   ("Johannesburg, S. Africa",   "South Africa North"),
    "southafricawest":    ("Cape Town, S. Africa",      "South Africa West"),
    "uaenorth":           ("Dubai, UAE",                "UAE North"),
    "uaecentral":         ("Abu Dhabi, UAE",            "UAE Central"),
    "qatarcentral":       ("Doha, Qatar",               "Qatar Central"),
    "israelcentral":      ("Tel Aviv, Israel",          "Israel Central"),
    "chilecentral":       ("Santiago, Chile",           "Chile Central"),
    "taiwannorth":        ("Taipei, Taiwan",            "Taiwan North"),
    "taiwannorthwest":    ("Taoyuan, Taiwan",           "Taiwan Northwest"),
}

# Xbox Live infrastructure ranges that aren't tagged in Azure ServiceTags.
# These are confirmed-not-game-server. Hardcoded because they aren't in
# the JSON.
XBOX_LIVE_PREFIXES = [
    "199.46.35.",       # Xbox Live auth/services
    "150.171.",         # Microsoft services backbone (also tagged AzureFrontDoor.Frontend partially)
]

# Cloudflare CDN — Halo uses this for asset delivery, never for game servers.
CDN_PREFIXES = [
    "104.18.",          # Cloudflare
    "104.19.",          # Cloudflare
    "2.18.",            # Akamai
]

# ---------------------------------------------------------------------------
# Loaded at import time
# ---------------------------------------------------------------------------

# Sorted lists of (network_int_start, network_int_end, region_id)
# Sorted by network_int_start for binary search.
_REGION_RANGES: list[tuple[int, int, str]] = []
_FRONT_DOOR_RANGES: list[tuple[int, int]] = []
_DATA_LOADED = False


def _load_data() -> None:
    """Decode and unpack the embedded ServiceTags data (lazy)."""
    global _REGION_RANGES, _FRONT_DOOR_RANGES, _DATA_LOADED
    if _DATA_LOADED:
        return

    b64 = _AZURE_DATA_B64.replace("\n", "").replace(" ", "")
    if len(b64) < 200 or b64.startswith("___"):
        # Placeholder not replaced — running from source pre-build.
        # Leave the lists empty; ip_to_region will return None.
        _DATA_LOADED = True
        return

    raw = gzip.decompress(base64.b64decode(b64))
    data = json.loads(raw)

    region_ranges = []
    for cidr_str, region in data.get("azure_regions", []):
        try:
            net = ipaddress.ip_network(cidr_str, strict=False)
            start = int(net.network_address)
            end = int(net.broadcast_address)
            region_ranges.append((start, end, region))
        except ValueError:
            continue

    fd_ranges = []
    for cidr_str in data.get("front_door", []):
        try:
            net = ipaddress.ip_network(cidr_str, strict=False)
            start = int(net.network_address)
            end = int(net.broadcast_address)
            fd_ranges.append((start, end))
        except ValueError:
            continue

    region_ranges.sort()
    fd_ranges.sort()
    _REGION_RANGES = region_ranges
    _FRONT_DOOR_RANGES = fd_ranges
    _DATA_LOADED = True


def _ip_to_int(ip: str) -> Optional[int]:
    try:
        return int(ipaddress.IPv4Address(ip))
    except (ValueError, ipaddress.AddressValueError):
        return None


def _binary_search_range(
    ranges: list,
    ip_int: int,
) -> Optional[tuple]:
    """Find the range that contains ip_int, or None.
    ranges is sorted by start. Each entry's first element is start, second is end.
    """
    if not ranges:
        return None
    # Find the rightmost range whose start <= ip_int
    idx = bisect.bisect_right(ranges, (ip_int, float('inf')))
    if idx == 0:
        return None
    candidate = ranges[idx - 1]
    if candidate[0] <= ip_int <= candidate[1]:
        return candidate
    return None


def is_azure_front_door(ip: str) -> bool:
    """True if the IP is in AzureFrontDoor.Frontend (Microsoft CDN edge)."""
    _load_data()
    ip_int = _ip_to_int(ip)
    if ip_int is None:
        return False
    return _binary_search_range(_FRONT_DOOR_RANGES, ip_int) is not None


def is_xbox_live_infra(ip: str) -> bool:
    """True if the IP is known Xbox Live infrastructure (NOT in Azure tags)."""
    return any(ip.startswith(p) for p in XBOX_LIVE_PREFIXES)


def is_cdn(ip: str) -> bool:
    """True if the IP is a known third-party CDN (Cloudflare, Akamai)."""
    return any(ip.startswith(p) for p in CDN_PREFIXES)


def ip_to_region(ip: str) -> tuple:
    """
    Given an IPv4 string, return (display_name, azure_region_full_name).
    Returns (None, None) if the IP is not in any Azure region.
    """
    _load_data()
    ip_int = _ip_to_int(ip)
    if ip_int is None:
        return None, None
    match = _binary_search_range(_REGION_RANGES, ip_int)
    if match is None:
        return None, None
    region_id = match[2]
    return REGION_DISPLAY.get(region_id, (region_id, region_id))


def reload_from_file(path: str) -> bool:
    """
    Reload Azure region data from a raw ServiceTags_Public_*.json file.
    Returns True on success, False on failure.

    This parses the full ServiceTags schema, not our compact embedded format:
      {
        "values": [
          {
            "name": "AzureCloud.eastus",
            "properties": {
              "addressPrefixes": ["1.2.3.0/24", ...]
            }
          },
          {
            "name": "AzureFrontDoor.Frontend",
            "properties": { "addressPrefixes": [...] }
          },
          ...
        ]
      }
    """
    global _REGION_RANGES, _FRONT_DOOR_RANGES, _DATA_LOADED

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return False

    if "values" not in data:
        return False

    region_ranges = []
    fd_ranges = []

    for v in data["values"]:
        name = v.get("name", "")
        prefixes = (v.get("properties") or {}).get("addressPrefixes", []) or []

        if name.startswith("AzureCloud.") and len(name) > len("AzureCloud."):
            region = name[len("AzureCloud."):]
            for cidr_str in prefixes:
                if ":" in cidr_str:  # skip IPv6
                    continue
                try:
                    net = ipaddress.ip_network(cidr_str, strict=False)
                    region_ranges.append(
                        (int(net.network_address), int(net.broadcast_address), region))
                except ValueError:
                    continue

        elif name == "AzureFrontDoor.Frontend":
            for cidr_str in prefixes:
                if ":" in cidr_str:
                    continue
                try:
                    net = ipaddress.ip_network(cidr_str, strict=False)
                    fd_ranges.append(
                        (int(net.network_address), int(net.broadcast_address)))
                except ValueError:
                    continue

    if not region_ranges:
        return False

    region_ranges.sort()
    fd_ranges.sort()
    _REGION_RANGES = region_ranges
    _FRONT_DOOR_RANGES = fd_ranges
    _DATA_LOADED = True
    return True


def describe(ip: str) -> str:
    """Diagnostic one-liner."""
    if is_azure_front_door(ip):
        return f"{ip}  [AzureFrontDoor.Frontend - CDN edge]"
    if is_cdn(ip):
        return f"{ip}  [third-party CDN]"
    if is_xbox_live_infra(ip):
        return f"{ip}  [Xbox Live infrastructure]"
    display, region = ip_to_region(ip)
    if display:
        return f"{ip}  [{display} -- {region}]"
    return f"{ip}  [unknown / non-Azure]"


if __name__ == "__main__":
    # Self-test
    test_ips = [
        "52.184.201.245",   # eastus2 game server
        "13.89.117.20",     # centralus matchmaker
        "68.220.132.149",   # eastus2 (was wrongly mapped to eastus before)
        "68.220.133.134",   # eastus2 (Xbox Live backbone)
        "104.18.124.108",   # Cloudflare
        "199.46.35.121",    # Xbox Live infra
        "172.193.105.8",    # eastus2 (MS service on Azure)
        "13.107.226.51",    # AzureFrontDoor.Frontend
        "150.171.109.184",  # AzureFrontDoor.Frontend
        "20.53.213.241",    # australiaeast (pfmsqos beacon)
        "1.2.3.4",          # unknown
    ]
    for ip in test_ips:
        print(describe(ip))
