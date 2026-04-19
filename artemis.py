"""
Artemis -- by Arkitexe
======================

Real-time Halo Infinite server location detection with deep packet analytics.
(Formerly Halo Server Radar. v15 of the detection engine.)

New in v15 (builds on v14):
    * Fixed false-positive match detection
        The v14 promotion check used PacketStats.current_pps(), which trims
        its sliding window relative to the last packet seen -- not wall clock.
        A short 2-3 second burst would leave the window "frozen" showing
        5+ PPS forever. If a stray keepalive arrived >15s later it bumped
        sustained_duration past 15s and the endpoint got confirmed as a
        "match" despite only ever having ~10 real packets.
      v15 adds two guards in _promote_candidates:
        (a) freshness: packets must be <2s old for pps to count
        (b) cumulative floor: need CONFIRM_MIN_PACKETS total packets
      Jay's 4/18 morning session showed 11 "matches" for 3 real games
      precisely because of this bug. Short bursts (3s, 6s, 9s "matches")
      can no longer get through.

    * Dual GIF strip at the top (rage + teabag side-by-side, always on)
    * Clearer match/allocation labeling
        - "[ALLOC]" tag instead of "[SHORT]" for attempts that slipped through
        - Peer (non-locked) UDP endpoints shown under each match row
        - Match log blocks now tag GAME_SERVER endpoints as [LOCKED] vs [PEER]

Detection engine (unchanged since v14):
    * Two-tier match detection
        Candidate phase: endpoint just observed, watching for sustained activity
        Confirmed phase: 5+ PPS sustained for 15+ seconds = real match
      Fixes the v13 false positives where every queue-allocation attempt was
      logged as a match.

    * Per-connection packet statistics via WinDivert
        - Packets per second (in / out / total)
        - Bytes per second (in / out / total)
        - Packet size histogram (buckets: <100, 100-199, 200-499, 500+)
        - Approximate RTT via packet-timing heuristic (no ICMP noise)
        - Jitter (stddev of inter-arrival times)
        - Direction counts

    * Queue health tracking during matchmaking
        - Allocation attempts counter
        - Queue age timer
        - Derived health tag: HOT / WARM / COLD / DESERTED

    * Live stats panel in GUI (toggleable)
    * Allocation attempt logging (toggleable)
    * Enhanced match log blocks with stats summary

Detection rules (same classification as v13, plus promotion thresholds):
    1. Endpoint with port 30000-31000 + Azure IP => CANDIDATE game server
       Must sustain 5+ PPS for 15+ seconds to be CONFIRMED as match
    2. Endpoint with UDP/3075 to Azure IP => QoS beacon (matchmaking active)
    3. TCP/443 => infrastructure, ignore
    4. FrontDoor / Xbox Live / CDN ranges => hard-excluded

EAC-safe: psutil only reads kernel network tables. WinDivert runs at the
Windows Filtering Platform layer, separate from the Halo process. Neither
opens a handle on HaloInfinite.exe.

Tested on Windows 10, Python 3.9+
"""

from __future__ import annotations

import base64
import ctypes
import io
import json
import logging
import os
import queue
import re
import socket
import sys
import threading
import time
import tkinter as tk
import urllib.error
import urllib.request
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, date, timedelta
from pathlib import Path
from tkinter import ttk
from typing import Optional

# ---------------------------------------------------------------------------
# Embedded resources (populated at build time)
# ---------------------------------------------------------------------------

# Placeholder gets replaced at build by a base64-encoded gzipped blob of
# azure_regions CIDR data. See build step at bottom of this file's sibling.
# When running from source, if the placeholder is still present the
# azure_regions module will fall back to reading ServiceTags JSON from disk.

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

try:
    import psutil
except ImportError:
    print("ERROR: pip install psutil", file=sys.stderr)
    sys.exit(1)

try:
    from azure_regions import (
        ip_to_region,
        is_azure_front_door,
        is_xbox_live_infra,
        is_cdn,
        reload_from_file as azure_reload_from_file,
    )
except ImportError:
    def ip_to_region(ip): return None, None
    def is_azure_front_door(ip): return False
    def is_xbox_live_infra(ip): return ip.startswith("199.46.35.")
    def is_cdn(ip): return ip.startswith("104.18.") or ip.startswith("104.19.")
    def azure_reload_from_file(path): return False

# pydivert is optional — degrade gracefully if unavailable or lacks admin
PYDIVERT_AVAILABLE = False
PYDIVERT_IMPORT_ERROR = None
try:
    import pydivert  # type: ignore
    PYDIVERT_AVAILABLE = True
except Exception as e:
    PYDIVERT_IMPORT_ERROR = str(e)


# ---------------------------------------------------------------------------
# Paths & Config
# ---------------------------------------------------------------------------

HALO_PROCESS_NAME = "HaloInfinite.exe"
POLL_INTERVAL = 3.0
PROCESS_CHECK_INTERVAL = 5.0

# PlayFab-documented port ranges
GAME_SERVER_PORT_MIN = 30000
GAME_SERVER_PORT_MAX = 31000
QOS_BEACON_PORT = 3075
HTTPS_PORTS = (443, 80, 8080)

# How many polls an endpoint must be seen before being considered a locked server
MIN_GAMESERVER_OBSERVATIONS = 2
# How many polls without seeing it before we drop the lock
GAMESERVER_FADE_POLLS = 3
# Age threshold for a UDP endpoint observation via pydivert (seconds)
UDP_OBSERVATION_TTL = 10.0

# v14: Match confirmation thresholds (two-tier detection)
# An endpoint must sustain this PPS for this duration to be promoted from
# CANDIDATE to CONFIRMED (counted as a real match).
CONFIRM_MIN_PPS = 5.0           # packets/sec averaged over confirm window
CONFIRM_MIN_DURATION_SEC = 15.0  # sustained for at least this long

# v15: Additional guardrails to prevent stale-window false positives.
# PacketStats.current_pps() trims its sliding window relative to the last
# packet seen, not wall-clock. A short burst could leave a stale "5+ PPS"
# reading that persisted forever. These guards fix that:
#
#   CONFIRM_MAX_PACKET_AGE_SEC: if the most recent packet is older than
#     this, the endpoint is considered stale and NOT eligible for promotion.
#     Must be <= STATS_WINDOW_SEC so that a stale endpoint's PPS reading
#     can't be "frozen" at a high value.
#
#   CONFIRM_MIN_PACKETS: cumulative packet floor. Without this, a 2-second
#     burst of 10 packets (pps=5, duration=2) could later be joined by a
#     stray keepalive at t=16s making duration=16. With this floor, the
#     total cumulative packets must match what a real sustained match
#     would produce. At 5 PPS * 15s = 75 packets minimum.
CONFIRM_MAX_PACKET_AGE_SEC = 2.5
CONFIRM_MIN_PACKETS = 75

# v14: Queue health tuning
# A "recent allocation attempt" is one within this many seconds
QUEUE_HEALTH_RECENT_WINDOW_SEC = 60.0
# HOT: >= 1 attempt in last 30s
QUEUE_HOT_WINDOW_SEC = 30.0
# DESERTED threshold: QoS active this long with zero attempts
QUEUE_DESERTED_AGE_SEC = 300.0

# v14: Stats tuning
STATS_WINDOW_SEC = 5.0  # sliding window for PPS/Bps
STATS_HISTOGRAM_BUCKETS = [(0, 99), (100, 199), (200, 499), (500, 1500)]

HOME = Path.home()


def _resolve_desktop_dir() -> Path:
    """Return the user's actual Desktop path.

    Windows users with OneDrive have their Desktop redirected to something
    like C:\\Users\\<name>\\OneDrive\\Desktop instead of the classic
    C:\\Users\\<name>\\Desktop. Python's ~/Desktop doesn't know about that
    redirection. We ask the Windows shell for the current FOLDERID_Desktop
    which correctly returns whichever path is active.

    Falls back gracefully on non-Windows systems (development / testing) to
    ~/Desktop if it exists, otherwise to HOME.
    """
    # Windows: use SHGetKnownFolderPath to ask for FOLDERID_Desktop
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes

            # FOLDERID_Desktop GUID: {B4BFCC3A-DB2C-424C-B029-7FE99A87C641}
            # struct GUID { DWORD d1; WORD d2; WORD d3; BYTE d4[8]; }
            class GUID(ctypes.Structure):
                _fields_ = [
                    ("Data1", wintypes.DWORD),
                    ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD),
                    ("Data4", ctypes.c_ubyte * 8),
                ]

            FOLDERID_Desktop = GUID(
                0xB4BFCC3A, 0xDB2C, 0x424C,
                (ctypes.c_ubyte * 8)(0xB0, 0x29, 0x7F, 0xE9,
                                       0x9A, 0x87, 0xC6, 0x41),
            )
            SHGetKnownFolderPath = ctypes.windll.shell32.SHGetKnownFolderPath
            SHGetKnownFolderPath.argtypes = [
                ctypes.POINTER(GUID), wintypes.DWORD, wintypes.HANDLE,
                ctypes.POINTER(ctypes.c_wchar_p),
            ]
            SHGetKnownFolderPath.restype = ctypes.c_long

            ppath = ctypes.c_wchar_p()
            hr = SHGetKnownFolderPath(
                ctypes.byref(FOLDERID_Desktop), 0, 0, ctypes.byref(ppath))
            if hr == 0 and ppath.value:
                result = Path(ppath.value)
                # Free the string Windows allocated for us
                ctypes.windll.ole32.CoTaskMemFree(ppath)
                if result.exists():
                    return result
        except Exception:
            pass

        # Last-resort Windows fallbacks if the shell call failed
        for candidate in (
            HOME / "OneDrive" / "Desktop",
            HOME / "Desktop",
        ):
            if candidate.exists():
                return candidate

    # Non-Windows (development only): try ~/Desktop, else HOME
    for candidate in (HOME / "Desktop", HOME):
        if candidate.exists():
            return candidate
    return HOME


# v15_r3: logs now live under the user's Desktop in a clean "Artemis Logs"
# folder so your friend can find them without digging through Documents.
# Previous location was %USERPROFILE%\Documents\HaloTracker.
DESKTOP_DIR = _resolve_desktop_dir()
OUTPUT_DIR = DESKTOP_DIR / "Artemis Logs"
DAILY_LOG_DIR = OUTPUT_DIR / "Daily Logs"
AZURE_CACHE_DIR = OUTPUT_DIR / "Azure Cache"
LIVE_LOG_FILE = OUTPUT_DIR / "artemis.log"  # main tail-friendly log
ENDPOINT_TRACE = OUTPUT_DIR / "endpoint_trace.jsonl"

for d in (OUTPUT_DIR, DAILY_LOG_DIR, AZURE_CACHE_DIR):
    try:
        d.mkdir(parents=True, exist_ok=True)
    except Exception:
        # If for some reason Desktop isn't writable, fall back to home.
        # Rare but possible on locked-down corporate machines.
        pass

# Microsoft ServiceTags download landing page
SERVICETAGS_LANDING = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
# Regex that matches the ServiceTags JSON download URL in the landing page HTML
SERVICETAGS_URL_RE = re.compile(
    r'https://download\.microsoft\.com/download/[^"\']*/ServiceTags_Public_(\d{8})\.json'
)


# ---------------------------------------------------------------------------
# Artemis resources (quotes, emojis, GIFs)
# ---------------------------------------------------------------------------

# Pillow is optional; without it we skip emoji + GIF rendering but the app
# still runs. Install with: pip install Pillow
PIL_AVAILABLE = False
try:
    from PIL import Image, ImageTk, ImageSequence  # type: ignore
    PIL_AVAILABLE = True
except Exception:
    Image = ImageTk = ImageSequence = None  # type: ignore

import random


def _resource_root() -> Path:
    """Locate the resources/ folder whether running from source or PyInstaller bundle."""
    # PyInstaller one-file extracts to _MEIPASS
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        p = Path(meipass) / "resources"
        if p.is_dir():
            return p
    # Alongside the script
    here = Path(__file__).resolve().parent
    p = here / "resources"
    if p.is_dir():
        return p
    # Fallback: cwd
    return Path.cwd() / "resources"


class ArtemisResources:
    """
    Loads quotes, emoji thumbnails, and GIF frames from the resources/ folder.
    All loads are best-effort: missing files degrade gracefully.
    """

    # Emoji display size in the history panel (pixels square)
    EMOJI_PX = 20
    # GIF display height (pixels). Width scales to maintain aspect ratio.
    GIF_HEIGHT_PX = 88

    def __init__(self) -> None:
        self.root = _resource_root()
        self.quotes: list[str] = []
        self.emoji_paths: list[Path] = []
        # Populated lazily once a Tk root exists
        self._emoji_cache: dict[Path, "ImageTk.PhotoImage"] = {}
        # GIF frames: list of PhotoImage per-frame, plus per-frame delays in ms
        self.gif_frames: dict[str, list["ImageTk.PhotoImage"]] = {}
        self.gif_delays: dict[str, list[int]] = {}

        self._load_quotes()
        self._discover_emojis()

    # ---- quotes ----

    def _load_quotes(self) -> None:
        qf = self.root / "quotes" / "all_quotes.txt"
        if not qf.is_file():
            return
        try:
            with open(qf, "r", encoding="utf-8", errors="replace") as fh:
                self.quotes = [line.strip() for line in fh if line.strip()]
        except Exception:
            self.quotes = []

    def random_quote(self) -> Optional[str]:
        if not self.quotes:
            return None
        return random.choice(self.quotes)

    # ---- emojis ----

    def _discover_emojis(self) -> None:
        ed = self.root / "emojis"
        if not ed.is_dir():
            return
        self.emoji_paths = sorted([p for p in ed.iterdir()
                                    if p.suffix.lower() in (".png", ".gif", ".jpg", ".jpeg")])

    def random_emoji(self) -> Optional[Path]:
        if not self.emoji_paths:
            return None
        return random.choice(self.emoji_paths)

    def get_emoji_photo(self, path: Path) -> Optional["ImageTk.PhotoImage"]:
        """
        Return a cached PhotoImage for an emoji, scaled to EMOJI_PX square.
        Returns None if Pillow is unavailable or the file can't be loaded.
        """
        if not PIL_AVAILABLE or path is None:
            return None
        if path in self._emoji_cache:
            return self._emoji_cache[path]
        try:
            im = Image.open(path)
            # For animated GIFs, take only the first frame
            if getattr(im, "is_animated", False):
                im.seek(0)
            im = im.convert("RGBA")
            im.thumbnail((self.EMOJI_PX, self.EMOJI_PX), Image.LANCZOS)
            photo = ImageTk.PhotoImage(im)
            self._emoji_cache[path] = photo
            return photo
        except Exception:
            return None

    # ---- gifs ----

    def load_gif(self, name: str) -> bool:
        """
        Pre-render all frames of the named GIF (without .gif extension) at
        display height GIF_HEIGHT_PX. Stores the frames + per-frame delays.
        Returns True if successfully loaded.
        """
        if not PIL_AVAILABLE:
            return False
        path = self.root / "gifs" / f"{name}.gif"
        if not path.is_file():
            return False
        try:
            im = Image.open(path)
            frames: list[ImageTk.PhotoImage] = []
            delays: list[int] = []
            for raw in ImageSequence.Iterator(im):
                frame = raw.convert("RGBA")
                # Scale to target height preserving aspect
                ratio = self.GIF_HEIGHT_PX / max(frame.height, 1)
                new_w = max(1, int(frame.width * ratio))
                new_h = self.GIF_HEIGHT_PX
                frame = frame.resize((new_w, new_h), Image.LANCZOS)
                frames.append(ImageTk.PhotoImage(frame))
                # Default to 60ms if the GIF didn't specify a duration
                delay = int(raw.info.get("duration", 60))
                if delay < 20:
                    delay = 60
                delays.append(delay)
            if not frames:
                return False
            self.gif_frames[name] = frames
            self.gif_delays[name] = delays
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Admin check (Windows)
# ---------------------------------------------------------------------------

def is_admin() -> bool:
    if os.name != "nt":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Logging (daily log files + live log)
# ---------------------------------------------------------------------------

class DailyLogHandler(logging.Handler):
    """
    Writes to a per-day log file under DAILY LOGS\\.
    Rolls over at midnight without restart.
    """

    def __init__(self) -> None:
        super().__init__()
        self._current_date: Optional[date] = None
        self._file = None
        self._lock = threading.Lock()

    def _open_for_today(self) -> None:
        today = date.today()
        if today == self._current_date and self._file is not None:
            return
        if self._file is not None:
            try:
                self._file.close()
            except Exception:
                pass
        self._current_date = today
        path = DAILY_LOG_DIR / f"artemis_{today.isoformat()}.log"
        try:
            self._file = open(path, "a", encoding="utf-8")
        except Exception:
            self._file = None

    def emit(self, record: logging.LogRecord) -> None:
        with self._lock:
            self._open_for_today()
            if self._file is None:
                return
            try:
                msg = self.format(record)
                self._file.write(msg + "\n")
                self._file.flush()
            except Exception:
                pass

    def close(self) -> None:
        with self._lock:
            if self._file is not None:
                try:
                    self._file.close()
                except Exception:
                    pass
                self._file = None
        super().close()


def _setup_logging() -> logging.Logger:
    logger = logging.getLogger("server_radar_v13")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %I:%M:%S %p",
    )

    # Live log (single file, always latest)
    try:
        fh = logging.FileHandler(LIVE_LOG_FILE, encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except Exception:
        pass

    # Daily log (auto-rolling)
    dh = DailyLogHandler()
    dh.setFormatter(fmt)
    logger.addHandler(dh)

    # stdout mirror for running from terminal
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    return logger


log = _setup_logging()


# ---------------------------------------------------------------------------
# VPN detection
# ---------------------------------------------------------------------------

VPN_NAME_PATTERNS = [
    # (display-name, regex)
    ("Mullvad",      re.compile(r"mullvad", re.IGNORECASE)),
    ("WireGuard",    re.compile(r"wireguard|wg_", re.IGNORECASE)),
    ("OpenVPN",      re.compile(r"openvpn|tap-windows", re.IGNORECASE)),
    ("ProtonVPN",    re.compile(r"protonvpn|proton", re.IGNORECASE)),
    ("NordVPN",      re.compile(r"nordvpn|nord", re.IGNORECASE)),
    ("ExpressVPN",   re.compile(r"expressvpn|express", re.IGNORECASE)),
    ("Cisco AnyConnect", re.compile(r"cisco\s*anyconnect|anyconnect", re.IGNORECASE)),
    ("TAP adapter",  re.compile(r"\btap\b", re.IGNORECASE)),
    ("TUN adapter",  re.compile(r"\btun\b", re.IGNORECASE)),
]


def detect_vpn() -> Optional[str]:
    """Return the display name of an active VPN adapter, or None."""
    try:
        if_stats = psutil.net_if_stats()
        if_addrs = psutil.net_if_addrs()
    except Exception:
        return None

    active_iface_names = [
        name for name, stats in if_stats.items()
        if stats.isup and name in if_addrs
    ]

    for iface in active_iface_names:
        # Only consider interfaces with an IPv4 that isn't loopback or link-local
        has_routable_v4 = False
        for addr in if_addrs.get(iface, []):
            if addr.family == socket.AF_INET:
                ip = addr.address
                if not ip.startswith(("127.", "169.254.", "0.")):
                    has_routable_v4 = True
                    break
        if not has_routable_v4:
            continue
        for display, pat in VPN_NAME_PATTERNS:
            if pat.search(iface):
                return display
    return None


# ---------------------------------------------------------------------------
# Endpoint classification
# ---------------------------------------------------------------------------

KIND_GAME_SERVER = "GAME_SERVER"
KIND_QOS_BEACON  = "QOS_BEACON"
KIND_HTTPS       = "HTTPS"
KIND_FRONT_DOOR  = "FRONT_DOOR"
KIND_XBOX_LIVE   = "XBOX_LIVE"
KIND_CDN         = "CDN"
KIND_OTHER       = "OTHER"


def classify_endpoint(ip: str, port: int, protocol: str) -> str:
    if is_azure_front_door(ip):
        return KIND_FRONT_DOOR
    if is_xbox_live_infra(ip):
        return KIND_XBOX_LIVE
    if is_cdn(ip):
        return KIND_CDN

    if GAME_SERVER_PORT_MIN <= port <= GAME_SERVER_PORT_MAX:
        display, _ = ip_to_region(ip)
        if display is not None:
            return KIND_GAME_SERVER
        return KIND_OTHER

    if protocol == "udp" and port == QOS_BEACON_PORT:
        return KIND_QOS_BEACON

    if protocol == "tcp" and port in HTTPS_PORTS:
        return KIND_HTTPS

    return KIND_OTHER


# ---------------------------------------------------------------------------
# Halo process discovery + TCP polling
# ---------------------------------------------------------------------------

def find_halo_pid() -> Optional[int]:
    name_lower = HALO_PROCESS_NAME.lower()
    halo_pids = []
    for p in psutil.process_iter(attrs=["name", "pid"]):
        try:
            if p.info["name"] and p.info["name"].lower() == name_lower:
                halo_pids.append(p.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if not halo_pids:
        return None
    if len(halo_pids) == 1:
        return halo_pids[0]

    try:
        conns = psutil.net_connections(kind="tcp")
    except Exception:
        return max(halo_pids)
    counts = {pid: 0 for pid in halo_pids}
    for c in conns:
        if (c.pid in counts and c.raddr
                and not c.raddr.ip.startswith("127.")
                and not c.raddr.ip.startswith("::1")):
            counts[c.pid] += 1
    return max(counts.items(), key=lambda kv: (kv[1], kv[0]))[0]


def get_halo_tcp_endpoints(pid: int) -> list:
    """Returns (ip, port, 'tcp') for HaloInfinite.exe's ESTABLISHED TCP remotes."""
    out = []
    try:
        conns = psutil.net_connections(kind="tcp")
    except Exception as e:
        log.debug(f"net_connections failed: {e}")
        return out
    for c in conns:
        if c.pid != pid or not c.raddr:
            continue
        if c.status != psutil.CONN_ESTABLISHED:
            continue
        ip = c.raddr.ip
        port = c.raddr.port
        if (ip.startswith("127.") or ip.startswith("::1") or ip == "::"
                or ip == "0.0.0.0" or port == 0):
            continue
        out.append((ip, port, "tcp"))
    return out


# ---------------------------------------------------------------------------
# UDP sniffer via WinDivert (pydivert)
# ---------------------------------------------------------------------------

class UdpSniffer(threading.Thread):
    """
    Uses pydivert/WinDivert to sniff UDP packets and report their remote
    endpoints to a shared queue.

    This runs in SNIFF mode so packets pass through normally — we only
    observe. The filter is narrow to avoid hogging the driver:
        udp and !loopback and (udp.DstPort >= 30000 and udp.DstPort <= 31000
                               or udp.DstPort == 3075
                               or udp.SrcPort >= 30000 and udp.SrcPort <= 31000
                               or udp.SrcPort == 3075)

    Only outbound packets are reported (they have the remote as DstAddr).
    """

    def __init__(self, observation_queue: queue.Queue) -> None:
        super().__init__(daemon=True, name="UdpSniffer")
        self._stop_evt = threading.Event()
        self.obs_q = observation_queue
        self.status = "not started"
        self.error: Optional[str] = None
        self._windivert = None

    @staticmethod
    def available_reason() -> tuple:
        """Return (ok: bool, message: str) - explains why UDP sniffing may not work."""
        if not PYDIVERT_AVAILABLE:
            return False, f"pydivert not installed: {PYDIVERT_IMPORT_ERROR}"
        if os.name != "nt":
            return False, "pydivert only supported on Windows"
        if not is_admin():
            return False, "WinDivert requires administrator privileges"
        return True, "available"

    def stop(self) -> None:
        self._stop_evt.set()
        try:
            if self._windivert is not None:
                self._windivert.close()
        except Exception:
            pass

    def run(self) -> None:
        ok, reason = self.available_reason()
        if not ok:
            self.status = "disabled"
            self.error = reason
            log.info(f"UDP sniffer disabled: {reason}")
            return

        filter_expr = (
            "udp and !loopback and ("
            "(udp.DstPort >= 30000 and udp.DstPort <= 31000) or "
            "(udp.SrcPort >= 30000 and udp.SrcPort <= 31000) or "
            "udp.DstPort == 3075 or udp.SrcPort == 3075"
            ")"
        )

        try:
            import pydivert as _pd
            # Open in SNIFF mode so packets pass through normally
            self._windivert = _pd.WinDivert(
                filter_expr,
                layer=_pd.Layer.NETWORK,
                flags=_pd.Flag.SNIFF,
            )
            self._windivert.open()
            self.status = "running"
            log.info(f"UDP sniffer active (filter: {filter_expr})")
        except Exception as e:
            self.status = "error"
            self.error = str(e)
            log.warning(f"UDP sniffer failed to open WinDivert: {e}")
            return

        try:
            while not self._stop_evt.is_set():
                try:
                    packet = self._windivert.recv()
                except Exception as e:
                    if not self._stop_evt.is_set():
                        log.debug(f"WinDivert recv error: {e}")
                    break

                try:
                    # We want the remote address. If packet is outbound, dst is remote.
                    # If inbound, src is remote.
                    if packet.is_outbound:
                        remote_ip = packet.dst_addr
                        remote_port = packet.dst_port
                        direction = "out"
                    else:
                        remote_ip = packet.src_addr
                        remote_port = packet.src_port
                        direction = "in"

                    # Skip private / loopback destinations
                    if (remote_ip.startswith("127.")
                            or remote_ip.startswith("10.")
                            or remote_ip.startswith("192.168.")
                            or remote_ip.startswith("169.254.")
                            or remote_ip.startswith("0.")):
                        continue

                    # Only care about our target port ranges
                    in_game_range = (GAME_SERVER_PORT_MIN <= remote_port
                                     <= GAME_SERVER_PORT_MAX)
                    is_qos = (remote_port == QOS_BEACON_PORT)
                    if not (in_game_range or is_qos):
                        continue

                    # Packet size (IP payload length includes UDP header + data)
                    try:
                        pkt_size = len(bytes(packet.raw))
                    except Exception:
                        pkt_size = 0

                    try:
                        self.obs_q.put_nowait({
                            "ip": remote_ip,
                            "port": remote_port,
                            "protocol": "udp",
                            "timestamp": time.time(),
                            "direction": direction,
                            "size": pkt_size,
                        })
                    except queue.Full:
                        pass
                except Exception as e:
                    log.debug(f"Error processing UDP packet: {e}")
                    continue
        finally:
            try:
                if self._windivert is not None:
                    self._windivert.close()
            except Exception:
                pass
            self.status = "stopped"
            log.info("UDP sniffer stopped.")


# ---------------------------------------------------------------------------
# Packet statistics (per-endpoint, built from WinDivert observations)
# ---------------------------------------------------------------------------

# Endpoint promotion state machine
STATE_OBSERVED  = "OBSERVED"    # just seen, watching
STATE_CANDIDATE = "CANDIDATE"   # game-server-like, watching for sustained activity
STATE_CONFIRMED = "CONFIRMED"   # real match (passed PPS + duration threshold)
STATE_ENDED     = "ENDED"       # was confirmed, now gone


class PacketStats:
    """
    Tracks per-endpoint packet statistics from WinDivert observations.

    Maintains:
      - Sliding window of (timestamp, direction, size) for PPS/Bps computation
      - Cumulative counters for match-total reporting
      - Packet size histogram
      - RTT approximation (time between outbound-then-inbound pairs)
      - Jitter (stddev of inter-arrival times for inbound packets)
    """

    def __init__(self) -> None:
        self.first_packet_ts: Optional[float] = None
        self.last_packet_ts: Optional[float] = None

        # Cumulative
        self.total_packets_in = 0
        self.total_packets_out = 0
        self.total_bytes_in = 0
        self.total_bytes_out = 0

        # Peak tracking (for match summary)
        self.peak_pps = 0.0
        self.peak_bps = 0.0

        # Size histogram: list of bucket counts, aligned with STATS_HISTOGRAM_BUCKETS
        self.size_hist = [0] * len(STATS_HISTOGRAM_BUCKETS)

        # Sliding window: deque of (timestamp, direction, size)
        self._window: deque = deque()

        # RTT estimation: last outbound timestamp (if no inbound yet seen after it)
        self._pending_outbound_ts: Optional[float] = None
        self._rtt_samples: deque = deque(maxlen=100)  # last 100 RTT samples

        # Jitter: inter-arrival times for inbound packets
        self._last_inbound_ts: Optional[float] = None
        self._inter_arrival_samples: deque = deque(maxlen=100)

    def observe(self, timestamp: float, direction: str, size: int) -> None:
        """Record a single packet observation."""
        if self.first_packet_ts is None:
            self.first_packet_ts = timestamp
        self.last_packet_ts = timestamp

        if direction == "in":
            self.total_packets_in += 1
            self.total_bytes_in += size
            # RTT: if we have a pending outbound, this inbound closes the pair
            if self._pending_outbound_ts is not None:
                rtt = timestamp - self._pending_outbound_ts
                if 0.001 < rtt < 1.0:  # ignore nonsense (<1ms or >1s)
                    self._rtt_samples.append(rtt)
                self._pending_outbound_ts = None
            # Jitter: inter-arrival time between consecutive inbound packets
            if self._last_inbound_ts is not None:
                delta = timestamp - self._last_inbound_ts
                if 0 < delta < 1.0:
                    self._inter_arrival_samples.append(delta)
            self._last_inbound_ts = timestamp
        else:  # out
            self.total_packets_out += 1
            self.total_bytes_out += size
            # Only overwrite pending outbound if none is waiting (first of a burst)
            if self._pending_outbound_ts is None:
                self._pending_outbound_ts = timestamp

        # Histogram bucket
        for i, (lo, hi) in enumerate(STATS_HISTOGRAM_BUCKETS):
            if lo <= size <= hi:
                self.size_hist[i] += 1
                break
        else:
            # Size beyond defined buckets — put in the last bucket
            self.size_hist[-1] += 1

        # Append to sliding window
        self._window.append((timestamp, direction, size))
        self._trim_window(timestamp)

        # Update peaks
        cur_pps = self.current_pps()
        cur_bps = self.current_bps()
        if cur_pps > self.peak_pps:
            self.peak_pps = cur_pps
        if cur_bps > self.peak_bps:
            self.peak_bps = cur_bps

    def _trim_window(self, now: float) -> None:
        cutoff = now - STATS_WINDOW_SEC
        while self._window and self._window[0][0] < cutoff:
            self._window.popleft()

    def current_pps(self) -> float:
        """Packets per second in the current sliding window."""
        if not self._window:
            return 0.0
        if self.last_packet_ts is None:
            return 0.0
        self._trim_window(self.last_packet_ts)
        if not self._window:
            return 0.0
        window_span = self._window[-1][0] - self._window[0][0]
        if window_span < 0.1:
            return 0.0
        return len(self._window) / window_span

    def current_pps_in(self) -> float:
        if not self._window:
            return 0.0
        self._trim_window(self.last_packet_ts or time.time())
        in_pkts = sum(1 for _, d, _ in self._window if d == "in")
        if not self._window:
            return 0.0
        window_span = self._window[-1][0] - self._window[0][0]
        if window_span < 0.1:
            return 0.0
        return in_pkts / window_span

    def current_pps_out(self) -> float:
        if not self._window:
            return 0.0
        self._trim_window(self.last_packet_ts or time.time())
        out_pkts = sum(1 for _, d, _ in self._window if d == "out")
        if not self._window:
            return 0.0
        window_span = self._window[-1][0] - self._window[0][0]
        if window_span < 0.1:
            return 0.0
        return out_pkts / window_span

    def current_bps(self) -> float:
        """Bytes per second in the current sliding window."""
        if not self._window:
            return 0.0
        self._trim_window(self.last_packet_ts or time.time())
        if not self._window:
            return 0.0
        total = sum(sz for _, _, sz in self._window)
        window_span = self._window[-1][0] - self._window[0][0]
        if window_span < 0.1:
            return 0.0
        return total / window_span

    def avg_rtt_ms(self) -> Optional[float]:
        if not self._rtt_samples:
            return None
        return (sum(self._rtt_samples) / len(self._rtt_samples)) * 1000.0

    def min_rtt_ms(self) -> Optional[float]:
        if not self._rtt_samples:
            return None
        return min(self._rtt_samples) * 1000.0

    def max_rtt_ms(self) -> Optional[float]:
        if not self._rtt_samples:
            return None
        return max(self._rtt_samples) * 1000.0

    def jitter_ms(self) -> Optional[float]:
        """Stddev of inter-arrival times for inbound packets (ms)."""
        if len(self._inter_arrival_samples) < 2:
            return None
        samples = list(self._inter_arrival_samples)
        mean = sum(samples) / len(samples)
        variance = sum((s - mean) ** 2 for s in samples) / len(samples)
        return (variance ** 0.5) * 1000.0

    def avg_packet_size(self) -> Optional[float]:
        total_pkts = self.total_packets_in + self.total_packets_out
        if total_pkts == 0:
            return None
        total_bytes = self.total_bytes_in + self.total_bytes_out
        return total_bytes / total_pkts

    def sustained_duration(self) -> float:
        """How long since the first packet (seconds)."""
        if self.first_packet_ts is None:
            return 0.0
        return (self.last_packet_ts or self.first_packet_ts) - self.first_packet_ts

    def total_packets(self) -> int:
        return self.total_packets_in + self.total_packets_out

    def total_bytes(self) -> int:
        return self.total_bytes_in + self.total_bytes_out

    def histogram_summary(self) -> str:
        """Short human-readable histogram string."""
        total = sum(self.size_hist)
        if total == 0:
            return "no packets"
        parts = []
        for (lo, hi), count in zip(STATS_HISTOGRAM_BUCKETS, self.size_hist):
            pct = (count / total) * 100
            if pct >= 1:
                if hi >= 1500:
                    parts.append(f"{lo}+: {pct:.0f}%")
                else:
                    parts.append(f"{lo}-{hi}: {pct:.0f}%")
        return ", ".join(parts) if parts else "no packets"


# ---------------------------------------------------------------------------
# Endpoint tracker (merges TCP + UDP observations)
# ---------------------------------------------------------------------------

@dataclass
class EndpointObservation:
    ip: str
    port: int
    protocol: str
    kind: str
    first_seen: float
    last_seen: float
    observation_count: int = 0
    state: str = STATE_OBSERVED  # v14 state machine
    stats: "PacketStats" = field(default_factory=PacketStats)
    # When CONFIRMED, remember when so we can compute queue-to-match time
    confirmed_at: Optional[float] = None


class EndpointTracker:
    """
    Tracks (ip, port, protocol) endpoints with timestamps rather than poll counts.
    Merges TCP (from psutil polls) and UDP packet observations (from pydivert).

    v14: adds a two-tier state machine. Endpoints move:
        OBSERVED -> CANDIDATE -> CONFIRMED -> ENDED
    An endpoint reaches CONFIRMED only when its stats show at least
    CONFIRM_MIN_PPS packets/sec sustained for CONFIRM_MIN_DURATION_SEC.
    Only CONFIRMED endpoints are eligible to become the locked match server.

    Ended endpoints that reached CONFIRMED are written as match blocks;
    ones that only reached CANDIDATE are reported as allocation attempts.
    """

    def __init__(self) -> None:
        self._endpoints: dict[tuple, EndpointObservation] = {}
        self._locked_key: Optional[tuple] = None
        self._qos_active_until: float = 0.0  # timestamp; true if now < this
        # Ended endpoints awaiting caller to drain (for match / allocation logs)
        self._ended_queue: list[EndpointObservation] = []

    def observe(self, ip: str, port: int, protocol: str) -> EndpointObservation:
        """
        Record a TCP-poll-style observation (just an endpoint seen).
        Returns the EndpointObservation so caller can feed stats too.
        """
        key = (ip, port, protocol)
        now = time.time()
        kind = classify_endpoint(ip, port, protocol)
        if kind == KIND_QOS_BEACON:
            self._qos_active_until = now + 5.0

        obs = self._endpoints.get(key)
        if obs is None:
            state = STATE_CANDIDATE if kind == KIND_GAME_SERVER else STATE_OBSERVED
            obs = EndpointObservation(
                ip=ip, port=port, protocol=protocol, kind=kind,
                first_seen=now, last_seen=now, observation_count=1,
                state=state,
            )
            self._endpoints[key] = obs
        else:
            obs.last_seen = now
            obs.observation_count += 1
            obs.kind = kind

        return obs

    def record_packet(self, ip: str, port: int, timestamp: float,
                       direction: str, size: int) -> None:
        """
        Record a packet observation from the UDP sniffer. Feeds endpoint's
        PacketStats AND serves as an 'observe' for endpoint liveness.
        """
        obs = self.observe(ip, port, "udp")
        obs.stats.observe(timestamp, direction, size)

    def _promote_candidates(self) -> None:
        """Check CANDIDATE endpoints and promote to CONFIRMED if thresholds met.

        v15: three guards before promotion, all of which must pass:

          (1) sustained_duration >= CONFIRM_MIN_DURATION_SEC
              First/last packet spread is at least 15 seconds.

          (2) current_pps >= CONFIRM_MIN_PPS, AND the last packet is fresh
              (within CONFIRM_MAX_PACKET_AGE_SEC of now). This is critical
              because current_pps uses a sliding window trimmed relative to
              the last-packet timestamp. If traffic stopped, the reading is
              frozen at whatever the final burst produced. Requiring fresh
              packets ensures we're seeing ongoing traffic, not a stale peak.

          (3) total packets >= CONFIRM_MIN_PACKETS. A real 15-second match at
              5 PPS has ~75 packets minimum. A 2-second burst of 10 packets
              followed by a stray keepalive 16s later looks sustained on
              duration but has nowhere near the packet count of an actual
              in-progress match.
        """
        now = time.time()
        for key, obs in self._endpoints.items():
            if obs.state != STATE_CANDIDATE:
                continue
            if obs.kind != KIND_GAME_SERVER:
                continue

            stats = obs.stats
            duration = stats.sustained_duration()
            pps = stats.current_pps()
            total_pkts = stats.total_packets()
            last_pkt_ts = stats.last_packet_ts

            # Guard (1): sustained duration floor
            if duration < CONFIRM_MIN_DURATION_SEC:
                continue

            # Guard (2): freshness. current_pps is only trustworthy if we've
            # seen a packet very recently; otherwise it's reporting a stale
            # window.
            if last_pkt_ts is None:
                continue
            if (now - last_pkt_ts) > CONFIRM_MAX_PACKET_AGE_SEC:
                continue
            if pps < CONFIRM_MIN_PPS:
                continue

            # Guard (3): cumulative packet floor. Catches the "two bursts
            # glued together by duration math" false positive.
            if total_pkts < CONFIRM_MIN_PACKETS:
                continue

            obs.state = STATE_CONFIRMED
            obs.confirmed_at = now

    def prune(self) -> None:
        """Drop endpoints we haven't seen recently. End CONFIRMED ones cleanly."""
        now = time.time()
        to_drop = []
        for key, obs in self._endpoints.items():
            if obs.kind == KIND_GAME_SERVER:
                fade = GAMESERVER_FADE_POLLS * POLL_INTERVAL
            elif obs.kind == KIND_QOS_BEACON:
                fade = UDP_OBSERVATION_TTL
            else:
                fade = 30.0
            if now - obs.last_seen > fade:
                to_drop.append(key)

        for key in to_drop:
            obs = self._endpoints.pop(key, None)
            if obs is None:
                continue
            # If this was a game-server endpoint that reached any meaningful
            # state, queue it for logging
            if obs.kind == KIND_GAME_SERVER:
                obs.state = STATE_ENDED
                self._ended_queue.append(obs)
            if key == self._locked_key:
                self._locked_key = None

    def drain_ended(self) -> list:
        """Return ended endpoints awaiting logging. Caller is responsible
        for writing them. Clears the internal queue."""
        out = list(self._ended_queue)
        self._ended_queue.clear()
        return out

    def pick_match_server(self) -> Optional[tuple]:
        """
        Return best CONFIRMED game-server endpoint or None.
        Only endpoints that have passed the PPS + duration threshold are
        candidates for the GUI "locked" display.
        """
        self._promote_candidates()

        now = time.time()
        best = []
        for key, obs in self._endpoints.items():
            if obs.state != STATE_CONFIRMED:
                continue
            if now - obs.last_seen > POLL_INTERVAL * 2:
                continue
            # Score: prefer higher PPS + longer active
            score = obs.stats.current_pps() * 100 + obs.stats.sustained_duration()
            best.append((score, key))

        if not best:
            return None
        best.sort(reverse=True)
        self._locked_key = best[0][1]
        return self._locked_key

    def get_endpoint(self, key: tuple) -> Optional[EndpointObservation]:
        return self._endpoints.get(key)

    def iter_candidates(self):
        """Yield all CANDIDATE (unconfirmed game-server) endpoints."""
        for key, obs in self._endpoints.items():
            if obs.state == STATE_CANDIDATE and obs.kind == KIND_GAME_SERVER:
                yield key, obs

    def iter_confirmed(self):
        """Yield all CONFIRMED endpoints."""
        for key, obs in self._endpoints.items():
            if obs.state == STATE_CONFIRMED:
                yield key, obs

    def is_qos_active(self) -> bool:
        return time.time() < self._qos_active_until

    def snapshot(self) -> dict:
        kind_counts = Counter(o.kind for o in self._endpoints.values())
        state_counts = Counter(o.state for o in self._endpoints.values())
        candidates = []
        for key, obs in self._endpoints.items():
            if obs.state == STATE_CANDIDATE and obs.kind == KIND_GAME_SERVER:
                candidates.append({
                    "endpoint": f"{obs.ip}:{obs.port}",
                    "pps": round(obs.stats.current_pps(), 1),
                    "age_sec": round(obs.stats.sustained_duration(), 1),
                })
        return {
            "endpoint_count": len(self._endpoints),
            "kind_counts": dict(kind_counts),
            "state_counts": dict(state_counts),
            "qos_active": self.is_qos_active(),
            "locked": list(self._locked_key) if self._locked_key else None,
            "candidates": candidates,
        }


# ---------------------------------------------------------------------------
# Queue health tracker
# ---------------------------------------------------------------------------

class QueueHealthTracker:
    """
    Tracks matchmaking queue state to derive a "queue health" indicator.

    Listens to:
      - QoS beacon activity (indicates matchmaking started)
      - CANDIDATE game-server endpoints appearing (allocation attempts)
      - CONFIRMED endpoints (match found, queue ended)

    Exposes:
      - is_in_queue: bool
      - queue_age_sec: float
      - allocation_attempts: int (total this queue)
      - recent_attempts: int (within HOT window)
      - health: one of HOT, WARM, COLD, DESERTED, or None if not queueing
      - qos_regions: int (distinct regions probed)
    """

    HEALTH_HOT      = "HOT"
    HEALTH_WARM     = "WARM"
    HEALTH_COLD     = "COLD"
    HEALTH_DESERTED = "DESERTED"

    def __init__(self) -> None:
        self._queue_started: Optional[float] = None
        self._attempt_times: list[float] = []   # timestamps of allocation attempts
        self._seen_attempts: set = set()        # (ip, port) we've already counted
        self._qos_regions: set = set()          # distinct Azure regions probed

    def on_qos_beacon(self, ip: str) -> None:
        """Called each time a QoS beacon packet is observed."""
        now = time.time()
        if self._queue_started is None:
            self._queue_started = now
        _, region = ip_to_region(ip)
        if region:
            self._qos_regions.add(region)

    def on_candidate_seen(self, key: tuple) -> None:
        """Called when a CANDIDATE game-server endpoint first appears."""
        if key in self._seen_attempts:
            return
        self._seen_attempts.add(key)
        now = time.time()
        if self._queue_started is None:
            self._queue_started = now
        self._attempt_times.append(now)

    def on_match_confirmed(self) -> None:
        """Called when a match is confirmed - ends the queue."""
        self.reset()

    def reset(self) -> None:
        self._queue_started = None
        self._attempt_times.clear()
        self._seen_attempts.clear()
        self._qos_regions.clear()

    def is_in_queue(self) -> bool:
        return self._queue_started is not None

    def queue_age_sec(self) -> float:
        if self._queue_started is None:
            return 0.0
        return time.time() - self._queue_started

    @property
    def allocation_attempts(self) -> int:
        return len(self._attempt_times)

    def recent_attempts(self, window_sec: float = QUEUE_HOT_WINDOW_SEC) -> int:
        """Attempts within the last `window_sec` seconds."""
        cutoff = time.time() - window_sec
        return sum(1 for t in self._attempt_times if t >= cutoff)

    @property
    def qos_regions_count(self) -> int:
        return len(self._qos_regions)

    def health(self) -> Optional[str]:
        """Derived health tag, or None if not in queue."""
        if not self.is_in_queue():
            return None
        age = self.queue_age_sec()
        recent = self.recent_attempts()
        total = self.allocation_attempts

        if recent >= 1:
            return self.HEALTH_HOT
        if total >= 1 and age < QUEUE_HEALTH_RECENT_WINDOW_SEC * 2:
            return self.HEALTH_WARM
        if age > QUEUE_DESERTED_AGE_SEC and total == 0:
            return self.HEALTH_DESERTED
        return self.HEALTH_COLD

    def queue_age_str(self) -> str:
        age = int(self.queue_age_sec())
        m, s = divmod(age, 60)
        return f"{m}m {s:02d}s" if m > 0 else f"{s}s"


# ---------------------------------------------------------------------------
# Match logger (structured daily match entries)
# ---------------------------------------------------------------------------

@dataclass
class MatchRecord:
    match_number: int
    started_at: datetime
    ended_at: Optional[datetime] = None
    server_ip: str = ""
    server_port: int = 0
    server_protocol: str = ""
    server_display: str = ""
    server_region: str = ""
    endpoints_observed: set = field(default_factory=set)  # (ip, port, protocol, kind)

    # v14 stats captured from PacketStats at match end
    peak_pps: float = 0.0
    avg_pps: float = 0.0
    total_packets_in: int = 0
    total_packets_out: int = 0
    total_bytes_in: int = 0
    total_bytes_out: int = 0
    avg_rtt_ms: Optional[float] = None
    min_rtt_ms: Optional[float] = None
    max_rtt_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    avg_packet_size: Optional[float] = None
    size_hist_summary: str = ""

    # v14 queue metadata (populated at match confirm-time)
    queue_time_sec: float = 0.0
    queue_attempts: int = 0

    @property
    def duration_str(self) -> str:
        if self.ended_at is None:
            return "in progress"
        dt = (self.ended_at - self.started_at).total_seconds()
        m = int(dt // 60)
        s = int(dt % 60)
        return f"{m}m {s:02d}s"


class MatchLogger:
    """
    v14: Tracks confirmed matches + optional allocation attempts.
    Driven by the EndpointTracker's state transitions.
    """

    def __init__(self, log_allocation_attempts: bool = True) -> None:
        self._match_count = 0
        self._current: Optional[MatchRecord] = None
        self._lock = threading.Lock()
        self.log_allocation_attempts = log_allocation_attempts

    @property
    def current_match(self) -> Optional[MatchRecord]:
        return self._current

    @property
    def match_count(self) -> int:
        return self._match_count

    def on_match_confirmed(self, obs: "EndpointObservation",
                             queue: "QueueHealthTracker",
                             display: str, region: str) -> MatchRecord:
        """
        Called when an endpoint is promoted to CONFIRMED state.
        Starts a new match record.
        """
        with self._lock:
            # Same endpoint already tracked? just return existing
            if (self._current is not None and self._current.ended_at is None
                    and self._current.server_ip == obs.ip
                    and self._current.server_port == obs.port):
                return self._current

            # Close previous match if one is still open
            if self._current is not None and self._current.ended_at is None:
                self._close_match()

            self._match_count += 1
            self._current = MatchRecord(
                match_number=self._match_count,
                started_at=datetime.now(),
                server_ip=obs.ip,
                server_port=obs.port,
                server_protocol=obs.protocol,
                server_display=display,
                server_region=region,
                queue_time_sec=queue.queue_age_sec(),
                queue_attempts=queue.allocation_attempts,
            )
            self._current.endpoints_observed.add(
                (obs.ip, obs.port, obs.protocol, KIND_GAME_SERVER))
            log.info(f"MATCH {self._match_count} CONFIRMED: "
                     f"{display} ({region}) -- {obs.ip}:{obs.port}/{obs.protocol} "
                     f"(queue: {queue.queue_age_str()}, "
                     f"attempts: {queue.allocation_attempts})")
            return self._current

    def on_endpoint_observed(self, ip: str, port: int, protocol: str,
                              kind: str) -> None:
        """Record an endpoint observation against the current match."""
        with self._lock:
            if self._current is None or self._current.ended_at is not None:
                return
            self._current.endpoints_observed.add((ip, port, protocol, kind))

    def on_match_ended(self, obs: Optional["EndpointObservation"] = None) -> None:
        """
        Called when the confirmed endpoint fades (match server gone).
        If obs is provided, captures its final stats into the match record.
        """
        with self._lock:
            if self._current is None or self._current.ended_at is not None:
                return
            if obs is not None and obs.stats is not None:
                self._current.peak_pps = obs.stats.peak_pps
                # avg_pps = total_packets / total_duration
                total_pkts = obs.stats.total_packets()
                duration = obs.stats.sustained_duration()
                self._current.avg_pps = (total_pkts / duration) if duration > 0 else 0.0
                self._current.total_packets_in = obs.stats.total_packets_in
                self._current.total_packets_out = obs.stats.total_packets_out
                self._current.total_bytes_in = obs.stats.total_bytes_in
                self._current.total_bytes_out = obs.stats.total_bytes_out
                self._current.avg_rtt_ms = obs.stats.avg_rtt_ms()
                self._current.min_rtt_ms = obs.stats.min_rtt_ms()
                self._current.max_rtt_ms = obs.stats.max_rtt_ms()
                self._current.jitter_ms = obs.stats.jitter_ms()
                self._current.avg_packet_size = obs.stats.avg_packet_size()
                self._current.size_hist_summary = obs.stats.histogram_summary()
            self._close_match()

    def on_allocation_failed(self, obs: "EndpointObservation") -> None:
        """
        Called when a CANDIDATE endpoint fades without ever being confirmed
        (queue allocation attempt that didn't stick).
        Logs it as a separate block IF log_allocation_attempts is enabled.
        """
        if not self.log_allocation_attempts:
            return
        display, region = ip_to_region(obs.ip)
        started = datetime.fromtimestamp(obs.stats.first_packet_ts or obs.first_seen)
        ended = datetime.fromtimestamp(obs.stats.last_packet_ts or obs.last_seen)
        duration_s = (obs.stats.last_packet_ts or obs.last_seen) - (
            obs.stats.first_packet_ts or obs.first_seen)
        lines = [
            "",
            "- - - ALLOCATION ATTEMPT (not a match) - - -",
            f" Attempted:  {started.strftime('%Y-%m-%d %I:%M:%S %p')}",
            f" Server:     {display or 'Unknown'} ({region or '-'})",
            f" IP:         {obs.ip}:{obs.port}/{obs.protocol}",
            f" Duration:   {duration_s:.1f}s",
            f" Packets:    {obs.stats.total_packets()} "
            f"(peak {obs.stats.peak_pps:.1f} PPS)",
            " Result:     Not promoted to match -- PPS/duration below threshold",
            "- - - end allocation attempt - - -",
        ]
        log.info("\n".join(lines))

    def force_flush(self) -> None:
        """On shutdown, close any open match."""
        with self._lock:
            if self._current is not None and self._current.ended_at is None:
                self._close_match()

    def _close_match(self) -> None:
        """Internal: finalize current match and write log entry."""
        if self._current is None:
            return
        self._current.ended_at = datetime.now()
        self._write_match_entry(self._current)

    def _write_match_entry(self, m: MatchRecord) -> None:
        """Write a structured match block to the daily log."""
        by_kind = {}
        for ip, port, proto, kind in sorted(m.endpoints_observed):
            by_kind.setdefault(kind, []).append((ip, port, proto))

        started = m.started_at.strftime("%Y-%m-%d %I:%M:%S %p")

        def fmt_bytes(n: int) -> str:
            for unit in ("B", "KB", "MB", "GB"):
                if n < 1024:
                    return f"{n:.1f} {unit}"
                n /= 1024
            return f"{n:.1f} TB"

        total_pkts = m.total_packets_in + m.total_packets_out
        total_bytes = m.total_bytes_in + m.total_bytes_out

        lines = [
            "",
            "=" * 56,
            f" MATCH {m.match_number} -- {started}",
            "=" * 56,
            f" Server:         {m.server_display} ({m.server_region})",
            f" IP:             {m.server_ip}:{m.server_port}/{m.server_protocol}",
            f" Duration:       {m.duration_str}",
        ]

        if m.queue_attempts > 0 or m.queue_time_sec > 0:
            qm, qs = divmod(int(m.queue_time_sec), 60)
            lines.append(f" Queue time:     {qm}m {qs:02d}s  "
                         f"({m.queue_attempts} allocation attempts)")

        if total_pkts > 0:
            lines.append(f" Peak PPS:       {m.peak_pps:.1f}")
            lines.append(f" Avg PPS:        {m.avg_pps:.1f}")
            lines.append(f" Total packets:  {total_pkts:,}  "
                         f"({m.total_packets_out:,} up / {m.total_packets_in:,} down)")
            lines.append(f" Total bytes:    {fmt_bytes(total_bytes)}  "
                         f"({fmt_bytes(m.total_bytes_out)} up / "
                         f"{fmt_bytes(m.total_bytes_in)} down)")

            if m.avg_rtt_ms is not None:
                rtt_str = f"{m.avg_rtt_ms:.1f} ms"
                if m.min_rtt_ms is not None and m.max_rtt_ms is not None:
                    rtt_str += f"  (min {m.min_rtt_ms:.0f} / max {m.max_rtt_ms:.0f})"
                lines.append(f" Avg RTT:        {rtt_str}")
            if m.jitter_ms is not None:
                lines.append(f" Jitter:         {m.jitter_ms:.2f} ms")
            if m.avg_packet_size is not None:
                lines.append(f" Packet size:    avg {m.avg_packet_size:.0f} B  "
                             f"({m.size_hist_summary})")

        lines.append(" Connections observed this match:")
        order = [KIND_GAME_SERVER, KIND_QOS_BEACON, KIND_HTTPS,
                 KIND_FRONT_DOOR, KIND_XBOX_LIVE, KIND_CDN, KIND_OTHER]
        # Category legend appended below the connections list
        LEGEND = {
            KIND_GAME_SERVER: "Halo gameplay / candidate servers (UDP :30000-31000)",
            KIND_QOS_BEACON:  "Azure region ping probes for matchmaking (UDP :3075)",
            KIND_HTTPS:       "Halo Waypoint / PlayFab / Xbox API backend (TCP :443)",
            KIND_FRONT_DOOR:  "Azure Front Door edge routing (TCP :443)",
            KIND_XBOX_LIVE:   "Xbox Live platform services (TCP :443)",
            KIND_CDN:         "Cloudflare / CDN for static content (TCP :443)",
            KIND_OTHER:       "Unclassified traffic",
        }
        seen_kinds = []
        for kind in order:
            endpoints = by_kind.get(kind, [])
            if not endpoints:
                continue
            seen_kinds.append(kind)
            if kind == KIND_GAME_SERVER:
                # Split into LOCKED (the match server) vs PEER/CANDIDATE (other
                # :30000-31000 endpoints that appeared during this match but were
                # not the one we were actually playing on).
                locked_key = (m.server_ip, m.server_port, m.server_protocol)
                locked_entries = [e for e in endpoints if e == locked_key]
                peer_entries   = [e for e in endpoints if e != locked_key]
                lines.append(f"   [{kind} / LOCKED]  (the server you played on)")
                if not locked_entries:
                    # Shouldn't happen, but be defensive
                    lines.append(f"     - {m.server_ip}:{m.server_port}/{m.server_protocol}"
                                 f"  ({m.server_region})")
                for ip, port, proto in locked_entries:
                    display, region = ip_to_region(ip)
                    region_info = f" ({region})" if region else ""
                    lines.append(f"     - {ip}:{port}/{proto}{region_info}  <-- LOCKED")
                if peer_entries:
                    lines.append(f"   [{kind} / PEER]    (candidate or transient; not the match server)")
                    for ip, port, proto in peer_entries:
                        display, region = ip_to_region(ip)
                        region_info = f" ({region})" if region else ""
                        lines.append(f"     - {ip}:{port}/{proto}{region_info}")
            else:
                lines.append(f"   [{kind}]")
                for ip, port, proto in endpoints:
                    display, region = ip_to_region(ip)
                    region_info = f" ({region})" if region else ""
                    lines.append(f"     - {ip}:{port}/{proto}{region_info}")
        # Legend (only for categories that actually appeared)
        if seen_kinds:
            lines.append(" Legend:")
            for kind in seen_kinds:
                desc = LEGEND.get(kind, "")
                if kind == KIND_GAME_SERVER:
                    lines.append(f"   GAME_SERVER/LOCKED  = the server you were actually playing on")
                    lines.append(f"   GAME_SERVER/PEER    = other :30000-31000 endpoints seen during match")
                    lines.append(f"                          (matchmaker candidates, brief probes, or peer relays)")
                else:
                    lines.append(f"   {kind:<18}= {desc}")
        lines.append("=" * 56)
        block = "\n".join(lines)
        log.info(block)


# ---------------------------------------------------------------------------
# ServiceTags update handling
# ---------------------------------------------------------------------------

class ServiceTagsUpdater:
    """
    Manual ServiceTags update. User clicks button, we fetch the download page,
    find the latest JSON URL, download it, and reload into the azure_regions
    module.

    All network IO is in a background thread to keep the GUI responsive.
    """

    def __init__(self, status_cb) -> None:
        """status_cb: callable(str) - posts status messages to the GUI."""
        self.status_cb = status_cb
        self._thread: Optional[threading.Thread] = None

    def start_update(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            self.status_cb("Update already in progress...")
            return
        self._thread = threading.Thread(target=self._run_update, daemon=True)
        self._thread.start()

    def _run_update(self) -> None:
        try:
            self.status_cb("[ Contacting Microsoft... ]")
            with urllib.request.urlopen(SERVICETAGS_LANDING, timeout=15) as r:
                html = r.read().decode("utf-8", errors="ignore")
        except Exception as e:
            self.status_cb(f"[ Failed to fetch landing page: {e} ]")
            log.warning(f"ServiceTags update: landing fetch failed: {e}")
            return

        match = SERVICETAGS_URL_RE.search(html)
        if match is None:
            self.status_cb("[ Could not find ServiceTags URL in page ]")
            log.warning("ServiceTags update: URL regex didn't match")
            return

        json_url = match.group(0)
        date_str = match.group(1)
        cache_path = AZURE_CACHE_DIR / f"ServiceTags_Public_{date_str}.json"

        # Check if we already have this version
        if cache_path.exists() and cache_path.stat().st_size > 100000:
            self.status_cb(f"[ Already up to date: {date_str} ]")
            log.info(f"ServiceTags: cached copy for {date_str} already present")
            # Ensure it's loaded into our in-memory map
            ok = azure_reload_from_file(str(cache_path))
            if ok:
                self.status_cb(f"[ Reloaded cached data: {date_str} ]")
            return

        self.status_cb(f"[ Downloading {date_str}... ]")
        try:
            with urllib.request.urlopen(json_url, timeout=60) as r:
                data = r.read()
        except Exception as e:
            self.status_cb(f"[ Download failed: {e} ]")
            log.warning(f"ServiceTags update: download failed: {e}")
            return

        try:
            cache_path.write_bytes(data)
        except Exception as e:
            self.status_cb(f"[ Cache write failed: {e} ]")
            return

        ok = azure_reload_from_file(str(cache_path))
        if ok:
            self.status_cb(f"[ Updated to {date_str} -- {len(data)//1024} KB ]")
            log.info(f"ServiceTags: updated to {date_str} ({len(data)} bytes)")
        else:
            self.status_cb(f"[ Downloaded but failed to parse {date_str} ]")


# ---------------------------------------------------------------------------
# Worker thread
# ---------------------------------------------------------------------------

class TrackerWorker(threading.Thread):
    def __init__(self, ui_queue: queue.Queue, match_logger: MatchLogger) -> None:
        super().__init__(daemon=True, name="TrackerWorker")
        self.ui_queue = ui_queue
        self.match_logger = match_logger
        self._stop_evt = threading.Event()
        self.tracker = EndpointTracker()
        self.queue_health = QueueHealthTracker()

        # UDP sniffer (optional)
        self.udp_obs_queue: queue.Queue = queue.Queue(maxsize=5000)
        self.udp_sniffer: Optional[UdpSniffer] = None

        self.halo_pid: Optional[int] = None
        self.last_process_check = 0.0
        self.last_state_sent: Optional[str] = None

        # VPN state (checked periodically)
        self.last_vpn_check = 0.0
        self.vpn_name: Optional[str] = None

        # Live stats push cadence (lighter than poll interval)
        self.last_stats_push = 0.0

    def start_udp_sniffer(self) -> None:
        """Try to start UDP sniffing. Safe to call multiple times."""
        if self.udp_sniffer is not None and self.udp_sniffer.is_alive():
            return
        ok, reason = UdpSniffer.available_reason()
        if not ok:
            log.info(f"UDP sniffer not started: {reason}")
            return
        self.udp_sniffer = UdpSniffer(self.udp_obs_queue)
        self.udp_sniffer.start()

    def udp_status(self) -> str:
        """Human-readable UDP status for GUI."""
        ok, reason = UdpSniffer.available_reason()
        if not ok:
            return f"UDP: {reason}"
        if self.udp_sniffer is None:
            return "UDP: not started"
        return f"UDP: {self.udp_sniffer.status}"

    def stop(self) -> None:
        self._stop_evt.set()
        if self.udp_sniffer is not None:
            self.udp_sniffer.stop()

    def _push_ui(self, msg: dict) -> None:
        self.ui_queue.put(msg)

    def _trace(self, snap: dict, extra: dict) -> None:
        try:
            with open(ENDPOINT_TRACE, "a", encoding="utf-8") as f:
                rec = {
                    "local_time": datetime.now().strftime("%Y-%m-%d %I:%M:%S %p"),
                    **snap, **extra,
                }
                f.write(json.dumps(rec) + "\n")
        except Exception:
            pass

    def _drain_udp_queue(self) -> int:
        """Pull UDP observations into the tracker, feeding packet stats."""
        n = 0
        try:
            while True:
                item = self.udp_obs_queue.get_nowait()
                ip = item["ip"]
                port = item["port"]
                ts = item.get("timestamp", time.time())
                direction = item.get("direction", "in")
                size = item.get("size", 0)
                self.tracker.record_packet(ip, port, ts, direction, size)
                # Feed queue health
                if port == QOS_BEACON_PORT:
                    self.queue_health.on_qos_beacon(ip)
                elif GAME_SERVER_PORT_MIN <= port <= GAME_SERVER_PORT_MAX:
                    # A new CANDIDATE game-server endpoint
                    self.queue_health.on_candidate_seen((ip, port))
                n += 1
                if n > 2000:
                    break
        except queue.Empty:
            pass
        return n

    def _push_live_stats(self) -> None:
        """Push current server's live stats to GUI if locked."""
        if self.tracker._locked_key is None:
            return
        obs = self.tracker.get_endpoint(self.tracker._locked_key)
        if obs is None:
            return
        s = obs.stats
        self._push_ui({
            "type": "live_stats",
            "pps_total": round(s.current_pps(), 1),
            "pps_in":    round(s.current_pps_in(), 1),
            "pps_out":   round(s.current_pps_out(), 1),
            "bps":       round(s.current_bps(), 0),
            "avg_rtt":   round(s.avg_rtt_ms(), 1) if s.avg_rtt_ms() else None,
            "min_rtt":   round(s.min_rtt_ms(), 1) if s.min_rtt_ms() else None,
            "max_rtt":   round(s.max_rtt_ms(), 1) if s.max_rtt_ms() else None,
            "jitter":    round(s.jitter_ms(), 2) if s.jitter_ms() else None,
            "total_packets": s.total_packets(),
            "total_bytes":   s.total_bytes(),
            "packets_in":    s.total_packets_in,
            "packets_out":   s.total_packets_out,
            "bytes_in":      s.total_bytes_in,
            "bytes_out":     s.total_bytes_out,
            "avg_packet_size": round(s.avg_packet_size(), 1) if s.avg_packet_size() else None,
            "size_hist":     s.histogram_summary(),
            "age_sec":       round(s.sustained_duration(), 1),
        })

    def _push_queue_info(self) -> None:
        """Push queue-health info to GUI."""
        self._push_ui({
            "type": "queue_info",
            "in_queue":   self.queue_health.is_in_queue(),
            "age_str":    self.queue_health.queue_age_str(),
            "age_sec":    round(self.queue_health.queue_age_sec(), 1),
            "attempts":   self.queue_health.allocation_attempts,
            "regions":    self.queue_health.qos_regions_count,
            "health":     self.queue_health.health(),
        })

    def run(self) -> None:
        log.info("=" * 60)
        log.info("Artemis by Arkitexe -- TCP + UDP + packet stats")
        log.info(f"Admin: {is_admin()}  |  pydivert available: {PYDIVERT_AVAILABLE}")
        log.info(f"Live log: {LIVE_LOG_FILE}")
        log.info(f"Daily logs: {DAILY_LOG_DIR}")
        log.info(f"Trace: {ENDPOINT_TRACE}")
        log.info(f"Match confirm threshold: {CONFIRM_MIN_PPS} PPS for "
                 f"{CONFIRM_MIN_DURATION_SEC}s sustained")
        log.info("=" * 60)

        # Initial VPN check
        self.vpn_name = detect_vpn()
        self._push_ui({"type": "vpn_status", "name": self.vpn_name})

        # Attempt to start UDP sniffer
        self.start_udp_sniffer()
        self._push_ui({"type": "udp_status", "text": self.udp_status()})

        while not self._stop_evt.is_set():
            now = time.time()

            # Periodic VPN re-check
            if now - self.last_vpn_check > 30.0:
                self.last_vpn_check = now
                new_vpn = detect_vpn()
                if new_vpn != self.vpn_name:
                    self.vpn_name = new_vpn
                    self._push_ui({"type": "vpn_status", "name": new_vpn})

            # Process check
            if now - self.last_process_check > PROCESS_CHECK_INTERVAL:
                self.last_process_check = now
                pid = find_halo_pid()
                if pid != self.halo_pid:
                    if pid is None:
                        log.info("Halo closed.")
                        self._push_ui({"type": "halo_status",
                                       "running": False, "pid": None})
                        self.match_logger.on_match_ended()  # close any open match
                        self.tracker = EndpointTracker()
                        self.queue_health.reset()
                        self.last_state_sent = None
                    elif self.halo_pid is None:
                        log.info(f"Halo detected (pid={pid}).")
                        self._push_ui({"type": "halo_status",
                                       "running": True, "pid": pid})
                        self.tracker = EndpointTracker()
                        self.queue_health.reset()
                    else:
                        log.info(f"Halo PID: {self.halo_pid} -> {pid}")
                        self.tracker = EndpointTracker()
                        self.queue_health.reset()
                    self.halo_pid = pid

            # Drain UDP packet queue (from WinDivert sniffer). Each packet
            # feeds endpoint stats AND queue-health tracker.
            udp_count = self._drain_udp_queue()

            # TCP polling (from psutil) - used as a backup signal for
            # endpoints. Does NOT feed packet stats.
            if self.halo_pid is not None:
                tcp_endpoints = get_halo_tcp_endpoints(self.halo_pid)
                for ip, port, proto in tcp_endpoints:
                    self.tracker.observe(ip, port, proto)

            # Prune stale endpoints. This queues ENDED endpoints for
            # logging (match-end or allocation-failed).
            self.tracker.prune()

            # Drain ended endpoints: decide whether each was a real match
            # or a failed allocation attempt, and log accordingly.
            for ended_obs in self.tracker.drain_ended():
                if ended_obs.confirmed_at is not None:
                    # This endpoint was confirmed at some point => real match.
                    # Capture the current match's duration BEFORE closing so we
                    # can notify the UI (for the rage/teabag GIF trigger).
                    closing_match = self.match_logger.current_match
                    # v15: capture peer game-server endpoints seen during this
                    # match (other UDP endpoints on 30000-31000 range that were
                    # NOT the locked server). These are the "extra UDPs" Jay
                    # saw in the GUI after matches end -- they're real, just
                    # not the match server.
                    peers = []
                    if closing_match is not None:
                        locked = (closing_match.server_ip,
                                  closing_match.server_port,
                                  closing_match.server_protocol)
                        for ip, port, proto, kind in closing_match.endpoints_observed:
                            if kind != KIND_GAME_SERVER:
                                continue
                            if (ip, port, proto) == locked:
                                continue
                            _, region = ip_to_region(ip)
                            peers.append({
                                "ip": ip, "port": port, "protocol": proto,
                                "region": region or "unknown region",
                            })
                    self.match_logger.on_match_ended(ended_obs)
                    if closing_match is not None and closing_match.ended_at is not None:
                        dur_sec = (closing_match.ended_at
                                   - closing_match.started_at).total_seconds()
                        self._push_ui({
                            "type": "match_ended",
                            "match_number": closing_match.match_number,
                            "duration_sec": dur_sec,
                            "display": closing_match.server_display,
                            "peers": peers,
                        })
                else:
                    # Candidate that never confirmed => allocation attempt
                    self.match_logger.on_allocation_failed(ended_obs)

            # Record every current endpoint against the current match
            # (for match log's "connections observed" list)
            if self.halo_pid is not None:
                for key, obs in self.tracker._endpoints.items():
                    self.match_logger.on_endpoint_observed(
                        obs.ip, obs.port, obs.protocol, obs.kind)

            snap = self.tracker.snapshot()
            self._trace(snap, {
                "udp_packets_processed": udp_count,
                "halo_pid": self.halo_pid,
                "queue_age_sec": round(self.queue_health.queue_age_sec(), 1),
                "queue_attempts": self.queue_health.allocation_attempts,
                "queue_health": self.queue_health.health(),
            })

            # Decide UI state
            if self.halo_pid is None:
                pass  # already sent halo_status
            else:
                key = self.tracker.pick_match_server()
                if key is not None:
                    ip, port, proto = key
                    display, region = ip_to_region(ip)
                    new_state = f"locked:{ip}:{port}:{proto}"
                    if new_state != self.last_state_sent:
                        obs = self.tracker.get_endpoint(key)
                        match = self.match_logger.on_match_confirmed(
                            obs, self.queue_health,
                            display or "Unknown", region or "")
                        self.queue_health.on_match_confirmed()
                        self._push_ui({
                            "type": "server",
                            "ip": ip, "port": port, "protocol": proto,
                            "display": display, "azure": region,
                            "match_number": match.match_number,
                        })
                        self.last_state_sent = new_state
                elif self.tracker.is_qos_active() or self.queue_health.is_in_queue():
                    if self.last_state_sent != "searching":
                        self._push_ui({"type": "searching"})
                        self.last_state_sent = "searching"
                else:
                    if self.last_state_sent is not None and (
                            self.last_state_sent.startswith("locked:")):
                        # Lock lost before prune caught it
                        pass  # match will close via drain_ended naturally
                    if self.last_state_sent != "no_server":
                        self._push_ui({"type": "no_server"})
                        self.last_state_sent = "no_server"

            # Push queue info every poll (it updates constantly)
            self._push_queue_info()

            # Push live stats every ~1s when locked (faster than POLL_INTERVAL)
            if now - self.last_stats_push > 1.0:
                self.last_stats_push = now
                self._push_live_stats()

            self._stop_evt.wait(POLL_INTERVAL)

        log.info("Worker stopping.")
        self.match_logger.force_flush()
        log.info("Worker stopped.")


# ---------------------------------------------------------------------------
# Pip-Boy style GUI
# ---------------------------------------------------------------------------

class ArtemisGUI:
    # Fallout RobCo green phosphor palette
    # GREEN_BRIGHT is the glowing foreground; GREEN_DIM is the darker/unlit text.
    GREEN_BRIGHT = "#4fffb0"   # bright phosphor white-green
    GREEN        = "#21cc6f"   # standard text
    GREEN_DIM    = "#0b7a3a"   # dim / unlit / secondary
    GREEN_FAINT  = "#053a1a"   # barely-lit label, borders
    SCREEN_BG    = "#071a0c"   # dark greenish-black screen background
    SCANLINE     = "#0a2815"   # horizontal scanline color
    BG           = "#000000"   # window background (behind the bezel)
    RED_WARN     = "#ff4040"

    # Beige plastic bezel (the physical RobCo terminal casing)
    BEZEL_LIGHT  = "#c9b079"
    BEZEL        = "#9e875b"
    BEZEL_SHADOW = "#6a5637"
    BEZEL_DARK   = "#453620"
    SCREW        = "#3d3020"
    VENT_DARK    = "#2a2115"
    LED_OFF      = "#5a2b13"
    LED_ON       = "#ff7a24"

    # Back-compat shims so any old code paths that reference AMBER still work
    AMBER        = GREEN
    AMBER_BRIGHT = GREEN_BRIGHT
    AMBER_DIM    = GREEN_DIM

    # Larger defaults to accommodate the bezel + GIF strip + footer toggles.
    # MIN_HEIGHT must be tall enough that the screen viewport (window height
    # minus bezel chrome of ~162px) always has room for every child widget
    # including the footer toggle row. Header (~40) + subtitle (~22) + gif
    # strip (~110) + status panel (~120) + history heading (~28) + history
    # minimum (~80) + footer two rows (~70) = ~470 of content. Add the
    # bezel chrome and you need ~640 window height minimum to guarantee
    # everything shows. We pad to 820 so there's always breathing room.
    MIN_WIDTH = 760
    MIN_HEIGHT = 820
    DEFAULT_WIDTH = 900
    DEFAULT_HEIGHT = 980

    # Bezel padding (how much beige plastic frames the screen)
    BEZEL_PAD_TOP    = 58
    BEZEL_PAD_BOTTOM = 88
    BEZEL_PAD_SIDE   = 46
    SCREEN_RADIUS    = 32   # rounded-corner radius of the screen cutout

    def __init__(self) -> None:
        self.ui_queue: queue.Queue = queue.Queue()
        # Allocation-attempt logging toggle (persisted in GUI state)
        self.log_allocation_attempts = True
        self.match_logger = MatchLogger(log_allocation_attempts=True)
        self.updater_thread: Optional[ServiceTagsUpdater] = None

        # Load resources (quotes, emojis, gifs)
        self.resources = ArtemisResources()

        self.root = tk.Tk()
        self.root.title("Artemis -- by Arkitexe")
        self.root.geometry(f"{self.DEFAULT_WIDTH}x{self.DEFAULT_HEIGHT}")
        self.root.minsize(self.MIN_WIDTH, self.MIN_HEIGHT)
        self.root.configure(bg=self.BG)
        self.root.attributes("-topmost", True)

        # Window icon: use the grunt .ico on Windows (taskbar + title bar),
        # or iconphoto with the PNG as a fallback on other platforms.
        try:
            icon_ico = self.resources.root / "artemis_icon.ico"
            icon_png = self.resources.root / "artemis_icon.png"
            if sys.platform == "win32" and icon_ico.exists():
                self.root.iconbitmap(default=str(icon_ico))
            elif PIL_AVAILABLE and icon_png.exists():
                from PIL import Image, ImageTk
                self._window_icon_img = ImageTk.PhotoImage(
                    Image.open(icon_png).resize((64, 64), Image.LANCZOS))
                self.root.iconphoto(True, self._window_icon_img)
        except Exception:
            pass  # cosmetic only, don't block launch

        self._mono_font = self._pick_mono_font()

        # State vars
        self.halo_running = False
        self.current_state = "init"  # init / scanning / searching / locked
        self.current_server: Optional[dict] = None
        self.match_history: deque = deque(maxlen=20)
        self.vpn_name: Optional[str] = None
        self.udp_status_text: str = "UDP: checking..."
        self.update_status_text: str = ""
        self.queue_info: Optional[dict] = None
        self.live_stats: Optional[dict] = None
        self.stats_panel_visible = False
        self._blink_state = False

        # GIF animation state (v15: both GIFs always animating, independent frames)
        self._gif_idx_left: int = 0
        self._gif_idx_right: int = 0
        self._gif_caption_until: float = 0.0

        # v14 back-compat shims so any older code path doesn't attribute-error
        self._gif_mode: str = "idle"
        self._gif_frame_index: int = 0
        self._gif_switch_until: float = 0.0

        # Legend panel visibility
        self.legend_visible = False

        # Preload GIFs if Pillow is available
        self.resources.load_gif("teabag")
        self.resources.load_gif("rage")

        self._build_layout()

        # ServiceTags updater (uses our status bar)
        self.updater = ServiceTagsUpdater(self._post_update_status)

        # Worker thread
        self.worker = TrackerWorker(self.ui_queue, self.match_logger)
        self.worker.start()

        # Poll message queue + redraw
        self.root.after(120, self._process_queue)
        self.root.after(600, self._blink_tick)
        self.root.after(100, self._initial_focus)
        self.root.after(80, self._gif_tick)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---- helpers ----

    def _pick_mono_font(self) -> str:
        try:
            from tkinter import font as tkfont
            families = set(tkfont.families(root=self.root))
            for f in ("Consolas", "Cascadia Mono", "Cascadia Code",
                      "Lucida Console", "Courier New", "Courier"):
                if f in families:
                    return f
        except Exception:
            pass
        return "Courier"

    def _initial_focus(self) -> None:
        try:
            self.root.focus_force()
        except Exception:
            pass

    def _post_update_status(self, text: str) -> None:
        # Called from background thread; use queue
        self.ui_queue.put({"type": "update_status", "text": text})

    # ---- layout ----

    def _build_layout(self) -> None:
        """
        Build the RobCo CRT terminal GUI: a procedural beige plastic bezel
        drawn on a Canvas behind the actual widgets, with a green-phosphor
        screen area that hosts all the content.
        """
        # The outermost bezel Canvas -- paints the physical terminal housing.
        # The actual Tk widgets live inside a transparent Frame placed on top
        # of the canvas's screen region.
        self.bezel_canvas = tk.Canvas(
            self.root, bg=self.BG, highlightthickness=0, borderwidth=0,
        )
        self.bezel_canvas.pack(fill=tk.BOTH, expand=True)
        self.bezel_canvas.bind("<Configure>", self._on_bezel_resize)

        # The screen area (green CRT face). Lives inside the bezel.
        self.screen_frame = tk.Frame(self.bezel_canvas, bg=self.SCREEN_BG)
        # Will be placed by _on_bezel_resize
        self._screen_window_id: Optional[int] = None

        # ---- screen contents ----

        # Header bar. The title uses a two-label stack to simulate phosphor
        # glow: a dimmer copy behind at slight offset creates the halo
        # suggestion that Tk can't natively render.
        self.header_frame = tk.Frame(self.screen_frame, bg=self.SCREEN_BG)
        self.header_frame.pack(fill=tk.X, padx=10, pady=(12, 4))

        # Title group: we use a Canvas so we can stack a "glow" copy behind
        # the sharp copy for a pseudo-bloom effect. Plain Tk labels can't
        # blur, but the dim backdrop still reads as light spillage.
        title_canvas = tk.Canvas(
            self.header_frame, bg=self.SCREEN_BG,
            highlightthickness=0, borderwidth=0,
            height=26,
        )
        title_canvas.pack(side=tk.LEFT, fill=tk.X, expand=True)
        # Glow layer (dim, slightly offset, larger)
        title_canvas.create_text(
            6, 14, text="ARTEMIS -- by Arkitexe",
            anchor="w", fill=self.GREEN_DIM,
            font=(self._mono_font, 16, "bold"),
        )
        # Bright sharp layer on top
        title_canvas.create_text(
            5, 13, text="ARTEMIS -- by Arkitexe",
            anchor="w", fill=self.GREEN_BRIGHT,
            font=(self._mono_font, 16, "bold"),
        )
        self.title_lbl = title_canvas  # keep a handle

        self.vpn_lbl = tk.Label(
            self.header_frame,
            text="",
            fg=self.GREEN_DIM, bg=self.SCREEN_BG,
            font=(self._mono_font, 10, "normal"),
            anchor="e",
        )
        self.vpn_lbl.pack(side=tk.RIGHT)

        # Subtitle line (ROBCO TERMLINK flavor) -- beefier
        self.subtitle_lbl = tk.Label(
            self.screen_frame,
            text=">>  HALO SERVER TRACKER  //  TERMLINK PROTOCOL v15  <<",
            fg=self.GREEN, bg=self.SCREEN_BG,
            font=(self._mono_font, 10, "bold"),
            anchor="w",
        )
        self.subtitle_lbl.pack(fill=tk.X, padx=10, pady=(0, 6))

        # GIF strip -- both GIFs always visible side-by-side at the top.
        # Left = TEABAG (celebration / win vibe), Right = RAGE (salt vibe).
        # They animate continuously regardless of match state. v14 had a
        # single slot that toggled between them; v15 shows both always.
        self.gif_frame = tk.Frame(
            self.screen_frame, bg=self.SCREEN_BG,
            highlightbackground=self.GREEN_FAINT, highlightthickness=1,
        )
        self.gif_frame.pack(fill=tk.X, padx=10, pady=(4, 4))

        # Inner frame so we can center the two gifs with equal weighting
        gif_inner = tk.Frame(self.gif_frame, bg=self.SCREEN_BG)
        gif_inner.pack(fill=tk.X, padx=6, pady=4)
        gif_inner.grid_columnconfigure(0, weight=1)
        gif_inner.grid_columnconfigure(1, weight=0)
        gif_inner.grid_columnconfigure(2, weight=1)
        gif_inner.grid_columnconfigure(3, weight=0)
        gif_inner.grid_columnconfigure(4, weight=1)

        # Left GIF (teabag)
        self.gif_label_left = tk.Label(
            gif_inner, bg=self.SCREEN_BG,
            fg=self.GREEN_DIM,
            text="[ install Pillow for gifs ]" if not PIL_AVAILABLE else "",
            font=(self._mono_font, 8, "italic"),
        )
        self.gif_label_left.grid(row=0, column=1, padx=6)

        self.gif_caption_lbl = tk.Label(
            gif_inner, bg=self.SCREEN_BG,
            fg=self.GREEN_DIM, text="",
            font=(self._mono_font, 9, "italic"),
        )
        self.gif_caption_lbl.grid(row=0, column=2, padx=8)

        # Right GIF (rage)
        self.gif_label_right = tk.Label(
            gif_inner, bg=self.SCREEN_BG,
            fg=self.GREEN_DIM,
            text="[ install Pillow for gifs ]" if not PIL_AVAILABLE else "",
            font=(self._mono_font, 8, "italic"),
        )
        self.gif_label_right.grid(row=0, column=3, padx=6)

        # Back-compat: older code paths referenced self.gif_label as the
        # single-gif slot. Point it at the left gif so legacy calls don't NPE.
        self.gif_label = self.gif_label_left

        # Status bar (current state)
        self.status_frame = tk.Frame(
            self.screen_frame, bg=self.SCREEN_BG,
            highlightbackground=self.GREEN_DIM, highlightthickness=1,
        )
        self.status_frame.pack(fill=tk.X, padx=10, pady=4)

        self.status_lbl = tk.Label(
            self.status_frame,
            text="[  INITIALIZING...  ]",
            fg=self.GREEN, bg=self.SCREEN_BG,
            font=(self._mono_font, 13, "bold"),
            anchor="center",
            pady=8,
        )
        self.status_lbl.pack(fill=tk.X)

        self.location_lbl = tk.Label(
            self.status_frame,
            text="",
            fg=self.GREEN_BRIGHT, bg=self.SCREEN_BG,
            font=(self._mono_font, 17, "bold"),
            anchor="center",
            pady=3,
        )
        self.location_lbl.pack(fill=tk.X)

        self.endpoint_lbl = tk.Label(
            self.status_frame,
            text="",
            fg=self.GREEN_DIM, bg=self.SCREEN_BG,
            font=(self._mono_font, 9, "normal"),
            anchor="center",
            pady=2,
        )
        self.endpoint_lbl.pack(fill=tk.X, pady=(0, 8))

        # Queue info label - visible during matchmaking
        self.queue_info_lbl = tk.Label(
            self.status_frame,
            text="",
            fg=self.GREEN, bg=self.SCREEN_BG,
            font=(self._mono_font, 9, "normal"),
            anchor="center",
            pady=2,
        )
        self.queue_info_lbl.pack(fill=tk.X, pady=(0, 6))

        # Live stats panel (hidden by default; toggled via button)
        self.stats_frame = tk.Frame(
            self.screen_frame, bg=self.SCREEN_BG,
            highlightbackground=self.GREEN_DIM, highlightthickness=1,
        )
        # NOT packed initially -- toggle button will pack/unpack it

        self.stats_header_lbl = tk.Label(
            self.stats_frame,
            text="=== LIVE CONNECTION STATS ===",
            fg=self.GREEN_BRIGHT, bg=self.SCREEN_BG,
            font=(self._mono_font, 9, "bold"),
            anchor="w",
        )
        self.stats_header_lbl.pack(fill=tk.X, padx=8, pady=(4, 2))

        self.stats_text_lbl = tk.Label(
            self.stats_frame,
            text=" (no active connection)",
            fg=self.GREEN, bg=self.SCREEN_BG,
            font=(self._mono_font, 9, "normal"),
            justify=tk.LEFT, anchor="w",
        )
        self.stats_text_lbl.pack(fill=tk.X, padx=8, pady=(0, 4))

        # Endpoint legend (hidden by default; toggled via button).
        # Shows the meaning of each UDP/TCP category with hover tooltips too.
        self.legend_frame = tk.Frame(
            self.screen_frame, bg=self.SCREEN_BG,
            highlightbackground=self.GREEN_DIM, highlightthickness=1,
        )
        # NOT packed initially

        legend_entries = [
            ("GAME_SERVER / LOCKED",
             "UDP :30000-31000 -- the server you're actually playing on. "
             "Sustains 5+ PPS for 15+ seconds."),
            ("GAME_SERVER / PEER",
             "UDP :30000-31000 -- candidate server the matchmaker briefly probed, "
             "or a transient peer relay. Not the match server."),
            ("QOS_BEACON",
             "UDP :3075 -- Azure region ping probes. Halo sends these during "
             "matchmaking to measure latency to each datacenter."),
            ("HTTPS",
             "TCP :443 -- Halo Waypoint, PlayFab session mgmt, stats, telemetry, "
             "Xbox API. Backend infrastructure, not gameplay."),
            ("FRONT_DOOR",
             "TCP :443 -- Azure Front Door edge routing (13.107.213.x / 13.107.246.x). "
             "Traffic steering layer."),
            ("XBOX_LIVE",
             "TCP :443 -- Xbox Live platform services (199.46.35.x). "
             "Auth, presence, social."),
            ("CDN",
             "TCP :443 -- Cloudflare / other CDN (104.18.x). "
             "Static content delivery."),
            ("OTHER",
             "Unclassified traffic that didn't match any of the above rules."),
        ]
        tk.Label(
            self.legend_frame,
            text="=== ENDPOINT CATEGORIES ===",
            fg=self.GREEN_BRIGHT, bg=self.SCREEN_BG,
            font=(self._mono_font, 9, "bold"),
            anchor="w",
        ).pack(fill=tk.X, padx=8, pady=(4, 2))

        for name, desc in legend_entries:
            row = tk.Frame(self.legend_frame, bg=self.SCREEN_BG)
            row.pack(fill=tk.X, padx=8, pady=1)
            name_lbl = tk.Label(
                row, text=f" {name:<22}", fg=self.GREEN_BRIGHT, bg=self.SCREEN_BG,
                font=(self._mono_font, 9, "bold"), anchor="w", width=24,
            )
            name_lbl.pack(side=tk.LEFT)
            desc_lbl = tk.Label(
                row, text=desc, fg=self.GREEN, bg=self.SCREEN_BG,
                font=(self._mono_font, 9, "normal"),
                anchor="w", justify="left", wraplength=520,
            )
            desc_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)
            # Simple tooltip on hover: echo description to the update status bar
            def _make_tt(d=desc):
                def enter(_e): self.update_status_lbl.configure(text=d, fg=self.GREEN_BRIGHT)
                def leave(_e): self.update_status_lbl.configure(text=self.update_status_text, fg=self.GREEN_DIM)
                return enter, leave
            ent, lev = _make_tt()
            name_lbl.bind("<Enter>", ent); name_lbl.bind("<Leave>", lev)
            desc_lbl.bind("<Enter>", ent); desc_lbl.bind("<Leave>", lev)

        # Match history heading
        self.history_heading = tk.Label(
            self.screen_frame,
            text="===  MATCH HISTORY  ===",
            fg=self.GREEN_BRIGHT, bg=self.SCREEN_BG,
            font=(self._mono_font, 12, "bold"),
            anchor="w",
        )
        self.history_heading.pack(fill=tk.X, padx=10, pady=(8, 2))

        # Scrollable history (tk.Text so we can use tags + embedded emoji images)
        self.history_container = tk.Frame(
            self.screen_frame, bg=self.SCREEN_BG,
            highlightbackground=self.GREEN_DIM, highlightthickness=1,
        )
        self.history_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=2)

        self.history_text = tk.Text(
            self.history_container,
            bg=self.SCREEN_BG,
            fg=self.GREEN,
            font=(self._mono_font, 10, "normal"),
            insertbackground=self.GREEN,
            selectbackground=self.GREEN_DIM,
            selectforeground=self.SCREEN_BG,
            borderwidth=0,
            highlightthickness=0,
            wrap="word",
            padx=10, pady=8,
            spacing1=2, spacing3=2,  # v15_r2: more breathing room between lines
            state=tk.DISABLED,
        )
        self.history_scroll = tk.Scrollbar(
            self.history_container,
            orient=tk.VERTICAL,
            command=self.history_text.yview,
            bg=self.SCREEN_BG, troughcolor=self.SCREEN_BG,
            activebackground=self.GREEN_DIM, highlightthickness=0,
            borderwidth=0,
        )
        self.history_text.configure(yscrollcommand=self.history_scroll.set)
        self.history_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.history_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.history_text.tag_configure(
            "match_label", foreground=self.GREEN_BRIGHT,
            font=(self._mono_font, 11, "bold"),
        )
        self.history_text.tag_configure(
            "candidate_label", foreground="#c9a43a",
            font=(self._mono_font, 11, "bold"),
        )
        self.history_text.tag_configure("location", foreground=self.GREEN,
                                        font=(self._mono_font, 10, "bold"))
        self.history_text.tag_configure("details", foreground=self.GREEN_DIM)
        self.history_text.tag_configure("empty", foreground=self.GREEN_DIM)
        self.history_text.tag_configure(
            "quote", foreground=self.GREEN_BRIGHT,
            font=(self._mono_font, 10, "italic"),
            lmargin1=28, lmargin2=28,
            spacing1=3, spacing3=3,
        )
        self.history_text.tag_configure(
            "peer", foreground="#c9a43a",
            font=(self._mono_font, 10, "italic"),
        )
        self.history_text.tag_configure(
            "separator", foreground=self.GREEN_FAINT,
        )
        self.history_text.tag_configure(
            "short_tag", foreground=self.RED_WARN,
            font=(self._mono_font, 9, "bold"),
        )
        self.history_text.tag_configure(
            "ended_tag", foreground=self.GREEN_DIM,
            font=(self._mono_font, 9, "bold"),
        )
        self.history_text.tag_configure(
            "live_tag", foreground=self.GREEN_BRIGHT,
            font=(self._mono_font, 9, "bold"),
        )

        # Footer: a two-row layout so the buttons don't crowd the status text.
        # CRITICAL: we pack this BEFORE the match history in Tk's internal
        # pack order (via before=self.history_container) AND with
        # side=tk.BOTTOM. The match history above uses expand=True, which
        # would otherwise consume ALL remaining vertical space and push
        # the footer toggles off-screen. The 'before' argument reorders
        # the footer ahead of history_container in Tk's layout queue so
        # the footer's natural height gets reserved first, then history
        # expands into whatever is left.
        self.footer_frame = tk.Frame(self.screen_frame, bg=self.SCREEN_BG)
        self.footer_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=(4, 10),
                               before=self.history_container)

        # Top row: buttons (right-aligned)
        footer_top = tk.Frame(self.footer_frame, bg=self.SCREEN_BG)
        footer_top.pack(fill=tk.X)

        self.update_btn = self._mk_term_button(
            footer_top, "[ CHECK FOR UPDATES ]", self._on_update_click)
        self.update_btn.pack(side=tk.RIGHT)

        self.legend_btn = self._mk_term_button(
            footer_top, "[ LEGEND: OFF ]", self._on_legend_toggle,
            dim=True)
        self.legend_btn.pack(side=tk.RIGHT, padx=(0, 4))

        self.stats_btn = self._mk_term_button(
            footer_top, "[ LIVE STATS: OFF ]", self._on_stats_toggle,
            dim=True)
        self.stats_btn.pack(side=tk.RIGHT, padx=(0, 4))

        self.log_attempts_btn = self._mk_term_button(
            footer_top, "[ LOG ATTEMPTS: ON ]", self._on_log_attempts_toggle)
        self.log_attempts_btn.pack(side=tk.RIGHT, padx=(0, 4))

        # Bottom row: status text (UDP status on left, update status on right)
        footer_bot = tk.Frame(self.footer_frame, bg=self.SCREEN_BG)
        footer_bot.pack(fill=tk.X, pady=(4, 0))

        self.udp_status_lbl = tk.Label(
            footer_bot,
            text=self.udp_status_text,
            fg=self.GREEN_DIM, bg=self.SCREEN_BG,
            font=(self._mono_font, 8, "normal"),
            anchor="w",
        )
        self.udp_status_lbl.pack(side=tk.LEFT)

        self.update_status_lbl = tk.Label(
            footer_bot,
            text="",
            fg=self.GREEN_DIM, bg=self.SCREEN_BG,
            font=(self._mono_font, 8, "normal"),
            anchor="e",
        )
        self.update_status_lbl.pack(side=tk.RIGHT)

        # Scanline overlay: painted directly on the bezel_canvas over the
        # screen area after each resize. We track the IDs so we can redraw.
        self._scanline_ids: list[int] = []
        self._frame_ids: list[int] = []

        self._redraw_history()

    # ---- bezel painting ----

    def _mk_term_button(self, parent: tk.Widget, text: str, cmd,
                        dim: bool = False) -> tk.Button:
        """Make a flat terminal-style button with green glow."""
        color = self.GREEN_DIM if dim else self.GREEN
        return tk.Button(
            parent, text=text, command=cmd,
            fg=color, bg=self.SCREEN_BG,
            activebackground=self.GREEN_DIM,
            activeforeground=self.SCREEN_BG,
            font=(self._mono_font, 9, "bold"),
            relief=tk.FLAT, borderwidth=1,
            highlightbackground=color,
            highlightthickness=1,
            padx=8, pady=2,
            cursor="hand2",
        )

    def _on_bezel_resize(self, event: tk.Event) -> None:
        """Repaint the bezel as a single Pillow-rendered image.

        v15_r2: upgraded from flat Canvas primitives to a Pillow composite
        that simulates actual plastic/glass depth:
          - Multi-stop vertical gradient on the bezel face (top-lit)
          - Inner bevel "shelf" around the screen cutout (bright top-left
            edge, dark bottom-right edge = illusion of depth)
          - Soft drop shadow under the bezel
          - Curved screen with phosphor bloom gradient
          - Scanline overlay + corner vignette on the screen
          - Reflection highlight on upper-left of glass
          - 3D vent slots, screws with highlights, glowing power LED
        Falls back to the old flat paint if Pillow is missing.
        """
        W, H = event.width, event.height
        if W < 60 or H < 60:
            return
        c = self.bezel_canvas

        # Clear previous image and scanlines
        if getattr(self, "_bezel_image_id", None) is not None:
            try:
                c.delete(self._bezel_image_id)
            except tk.TclError:
                pass
        for cid in getattr(self, "_frame_ids", []):
            try:
                c.delete(cid)
            except tk.TclError:
                pass
        for cid in getattr(self, "_scanline_ids", []):
            try:
                c.delete(cid)
            except tk.TclError:
                pass
        self._frame_ids = []
        self._scanline_ids = []

        # Screen area geometry (shared between flat + image paths)
        pad = 16
        bezel_x0, bezel_y0 = pad, pad
        bezel_x1, bezel_y1 = W - pad, H - pad
        screen_x0 = bezel_x0 + self.BEZEL_PAD_SIDE
        screen_y0 = bezel_y0 + self.BEZEL_PAD_TOP
        screen_x1 = bezel_x1 - self.BEZEL_PAD_SIDE
        screen_y1 = bezel_y1 - self.BEZEL_PAD_BOTTOM

        if screen_x1 - screen_x0 < 200 or screen_y1 - screen_y0 < 200:
            return

        # Try the Pillow path first; fall back to flat primitives if unavailable.
        if PIL_AVAILABLE:
            self._paint_bezel_pillow(W, H,
                                      bezel_x0, bezel_y0, bezel_x1, bezel_y1,
                                      screen_x0, screen_y0, screen_x1, screen_y1)
        else:
            self._paint_bezel_flat(W, H,
                                    bezel_x0, bezel_y0, bezel_x1, bezel_y1,
                                    screen_x0, screen_y0, screen_x1, screen_y1)

        # Place/update the screen_frame widget container on top of the bezel.
        inner_margin = 10
        sw = screen_x1 - screen_x0 - 2 * inner_margin
        sh = screen_y1 - screen_y0 - 2 * inner_margin
        if self._screen_window_id is None:
            self._screen_window_id = c.create_window(
                screen_x0 + inner_margin, screen_y0 + inner_margin,
                anchor="nw",
                window=self.screen_frame, width=sw, height=sh,
            )
        else:
            c.coords(self._screen_window_id,
                     screen_x0 + inner_margin, screen_y0 + inner_margin)
            c.itemconfigure(self._screen_window_id, width=sw, height=sh)
        c.tag_raise(self._screen_window_id)

    # ----- Pillow-rendered bezel (the nice path) -----

    def _paint_bezel_pillow(self, W, H,
                            bezel_x0, bezel_y0, bezel_x1, bezel_y1,
                            screen_x0, screen_y0, screen_x1, screen_y1) -> None:
        """Render the entire bezel + screen glass as one Pillow image.

        The image is composited onto a single tk.PhotoImage displayed as the
        base of the Canvas. Widgets still go inside the screen_frame on top.
        """
        from PIL import Image, ImageDraw, ImageFilter

        # Work in an RGBA image covering the whole canvas.
        img = Image.new("RGBA", (W, H), (0, 0, 0, 255))
        draw = ImageDraw.Draw(img, "RGBA")

        # --- 1. Drop shadow under the bezel (soft black blur) ---
        shadow = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        sd = ImageDraw.Draw(shadow)
        sd.rounded_rectangle(
            [bezel_x0 + 6, bezel_y0 + 10, bezel_x1 + 6, bezel_y1 + 12],
            radius=22, fill=(0, 0, 0, 160),
        )
        shadow = shadow.filter(ImageFilter.GaussianBlur(radius=10))
        img.alpha_composite(shadow)

        # --- 2. Bezel face: vertical gradient from highlight to darker beige ---
        bezel_w = bezel_x1 - bezel_x0
        bezel_h = bezel_y1 - bezel_y0
        grad = Image.new("RGB", (1, bezel_h), (0, 0, 0))
        top_color    = (222, 196, 138)  # lighter beige
        mid_color    = (182, 156, 100)  # standard beige
        bottom_color = (120, 100, 62)   # darker beige near base
        gpx = grad.load()
        for y in range(bezel_h):
            t = y / max(1, bezel_h - 1)
            if t < 0.5:
                # top -> mid
                u = t / 0.5
                r = int(top_color[0] * (1 - u) + mid_color[0] * u)
                g = int(top_color[1] * (1 - u) + mid_color[1] * u)
                b = int(top_color[2] * (1 - u) + mid_color[2] * u)
            else:
                u = (t - 0.5) / 0.5
                r = int(mid_color[0] * (1 - u) + bottom_color[0] * u)
                g = int(mid_color[1] * (1 - u) + bottom_color[1] * u)
                b = int(mid_color[2] * (1 - u) + bottom_color[2] * u)
            gpx[0, y] = (r, g, b)
        grad = grad.resize((bezel_w, bezel_h))

        # Mask: rounded bezel outline
        bezel_mask = Image.new("L", (W, H), 0)
        bmd = ImageDraw.Draw(bezel_mask)
        bmd.rounded_rectangle(
            [bezel_x0, bezel_y0, bezel_x1, bezel_y1],
            radius=20, fill=255,
        )
        bezel_rgba = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        bezel_rgba.paste(grad, (bezel_x0, bezel_y0))
        img.paste(bezel_rgba, (0, 0), bezel_mask)

        # --- 3. Subtle plastic noise texture on the bezel (1% opacity) ---
        try:
            import random
            noise = Image.new("L", (bezel_w // 2, bezel_h // 2))
            npx = noise.load()
            rand = random.Random(0xC0FFEE)  # deterministic
            for yy in range(noise.height):
                for xx in range(noise.width):
                    npx[xx, yy] = rand.randint(110, 140)
            noise = noise.resize((bezel_w, bezel_h), Image.BILINEAR)
            noise_rgba = Image.merge("RGBA", (noise, noise, noise,
                                               Image.new("L", noise.size, 18)))
            noise_clipped = Image.new("RGBA", (W, H), (0, 0, 0, 0))
            noise_clipped.paste(noise_rgba, (bezel_x0, bezel_y0), bezel_mask.crop(
                (bezel_x0, bezel_y0, bezel_x1, bezel_y1)))
            img.alpha_composite(noise_clipped)
        except Exception:
            pass

        # --- 4. Top-edge highlight on the bezel (specular strip) ---
        hl = Image.new("RGBA", (W, 24), (0, 0, 0, 0))
        hld = ImageDraw.Draw(hl)
        for i in range(24):
            a = max(0, 200 - i * 9)
            hld.rectangle([bezel_x0 + 8, i, bezel_x1 - 8, i + 1],
                          fill=(255, 235, 190, a))
        img.alpha_composite(hl, (0, bezel_y0 + 2))

        # --- 5. Screen "shelf" recess: dark ring immediately around screen ---
        shelf_pad = 6
        shelf_rect = [screen_x0 - shelf_pad, screen_y0 - shelf_pad,
                      screen_x1 + shelf_pad, screen_y1 + shelf_pad]
        # Dark bottom-right cast (inner bevel shadow)
        shelf_shadow = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        ssd = ImageDraw.Draw(shelf_shadow)
        ssd.rounded_rectangle(
            [shelf_rect[0] + 2, shelf_rect[1] + 2,
             shelf_rect[2] + 4, shelf_rect[3] + 4],
            radius=self.SCREEN_RADIUS + 4, fill=(40, 30, 15, 200),
        )
        shelf_shadow = shelf_shadow.filter(ImageFilter.GaussianBlur(radius=3))
        img.alpha_composite(shelf_shadow)
        # Bright top-left cast (inner bevel highlight)
        shelf_hl = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        shd = ImageDraw.Draw(shelf_hl)
        shd.rounded_rectangle(
            [shelf_rect[0] - 3, shelf_rect[1] - 3,
             shelf_rect[2] - 1, shelf_rect[3] - 1],
            radius=self.SCREEN_RADIUS + 4, fill=(255, 240, 200, 90),
        )
        shelf_hl = shelf_hl.filter(ImageFilter.GaussianBlur(radius=2))
        img.alpha_composite(shelf_hl)

        # --- 6. Screen glass: dark phosphor base + bloom gradient ---
        screen_w = screen_x1 - screen_x0
        screen_h = screen_y1 - screen_y0
        screen_mask = Image.new("L", (W, H), 0)
        smd = ImageDraw.Draw(screen_mask)
        smd.rounded_rectangle(
            [screen_x0, screen_y0, screen_x1, screen_y1],
            radius=self.SCREEN_RADIUS, fill=255,
        )
        # Base: very dark green
        screen_base = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        sbd = ImageDraw.Draw(screen_base)
        sbd.rounded_rectangle(
            [screen_x0, screen_y0, screen_x1, screen_y1],
            radius=self.SCREEN_RADIUS, fill=(7, 26, 12, 255),
        )
        img.alpha_composite(screen_base)

        # Radial phosphor bloom: subtle green glow brightest at center
        bloom = Image.new("RGBA", (screen_w, screen_h), (0, 0, 0, 0))
        bd = ImageDraw.Draw(bloom)
        cx, cy = screen_w // 2, screen_h // 2
        max_r = int((screen_w ** 2 + screen_h ** 2) ** 0.5 / 2)
        # Draw concentric ovals from large to small, stronger green as we go in
        for i in range(10):
            t = i / 10
            r = int(max_r * (1 - t))
            alpha = int(50 * (1 - t))  # subtle
            green_boost = int(12 * (1 - t))
            bd.ellipse([cx - r, cy - int(r * screen_h / screen_w),
                        cx + r, cy + int(r * screen_h / screen_w)],
                       fill=(30, 90 + green_boost, 45, alpha))
        bloom = bloom.filter(ImageFilter.GaussianBlur(radius=18))
        bloom_positioned = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        bloom_positioned.paste(bloom, (screen_x0, screen_y0))
        # Clip to screen mask
        bp = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        bp.paste(bloom_positioned, (0, 0), screen_mask)
        img.alpha_composite(bp)

        # --- 7. Corner vignette on screen (darkens edges) ---
        vignette = Image.new("RGBA", (screen_w, screen_h), (0, 0, 0, 0))
        vd = ImageDraw.Draw(vignette)
        for i in range(20, 0, -1):
            a = int(110 * (i / 20) ** 2)
            vd.rounded_rectangle(
                [i, i, screen_w - i, screen_h - i],
                radius=max(2, self.SCREEN_RADIUS - i),
                outline=(0, 0, 0, a // 6), width=1,
            )
        vignette = vignette.filter(ImageFilter.GaussianBlur(radius=6))
        vp = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        vp.paste(vignette, (screen_x0, screen_y0))
        vp_clipped = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        vp_clipped.paste(vp, (0, 0), screen_mask)
        img.alpha_composite(vp_clipped)

        # --- 8. Scanlines as semi-transparent horizontal lines ---
        scan = Image.new("RGBA", (screen_w, screen_h), (0, 0, 0, 0))
        sd = ImageDraw.Draw(scan)
        for y in range(0, screen_h, 3):
            sd.rectangle([0, y, screen_w, y + 1], fill=(0, 0, 0, 35))
        sp = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        sp.paste(scan, (screen_x0, screen_y0))
        sp_clipped = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        sp_clipped.paste(sp, (0, 0), screen_mask)
        img.alpha_composite(sp_clipped)

        # --- 9. Reflection highlight (curved glass catches light top-left) ---
        refl = Image.new("RGBA", (screen_w // 2, screen_h // 3), (0, 0, 0, 0))
        rd = ImageDraw.Draw(refl)
        for i in range(refl.height):
            t = i / refl.height
            a = int(60 * (1 - t) ** 2)
            rd.rectangle([0, i, int(refl.width * (1 - t * 0.4)), i + 1],
                         fill=(200, 255, 220, a))
        refl = refl.filter(ImageFilter.GaussianBlur(radius=14))
        rp = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        rp.paste(refl, (screen_x0, screen_y0))
        rp_clipped = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        rp_clipped.paste(rp, (0, 0), screen_mask)
        img.alpha_composite(rp_clipped)

        # --- 10. Hardware details below the screen ---
        hw_y0 = screen_y1 + 14
        hw_y1 = bezel_y1 - 14
        bd_draw = ImageDraw.Draw(img)

        # Vent slot
        vent_w = int((bezel_x1 - bezel_x0) * 0.55)
        vent_x0 = bezel_x0 + (bezel_x1 - bezel_x0 - vent_w) // 2
        vent_x1 = vent_x0 + vent_w
        vent_cy = (hw_y0 + hw_y1) // 2
        vh = min(28, hw_y1 - hw_y0 - 8)
        vy0 = vent_cy - vh // 2
        vy1 = vent_cy + vh // 2
        # Recessed dark vent (gradient top-dark to slightly lighter bottom)
        bd_draw.rounded_rectangle(
            [vent_x0, vy0, vent_x1, vy1],
            radius=4, fill=(20, 14, 8, 255),
        )
        # Top inner shadow
        bd_draw.line([vent_x0 + 2, vy0 + 1, vent_x1 - 2, vy0 + 1],
                     fill=(0, 0, 0, 255), width=1)
        # Vertical ribs (each with its own mini-shadow + highlight)
        for x in range(vent_x0 + 6, vent_x1 - 4, 5):
            bd_draw.line([x, vy0 + 3, x, vy1 - 3], fill=(45, 32, 18), width=1)
            bd_draw.line([x + 1, vy0 + 3, x + 1, vy1 - 3], fill=(90, 70, 40), width=1)
        # Bottom inner highlight
        bd_draw.line([vent_x0 + 2, vy1 - 1, vent_x1 - 2, vy1 - 1],
                     fill=(140, 110, 60), width=1)

        # Screws flanking the vent (3D: radial-ish highlight)
        def screw(cx, cy, r=8):
            # Dark outer ring (depth)
            bd_draw.ellipse([cx - r - 1, cy - r - 1, cx + r + 1, cy + r + 1],
                            fill=(30, 22, 12))
            # Metal body (slight gradient approximation)
            bd_draw.ellipse([cx - r, cy - r, cx + r, cy + r],
                            fill=(78, 68, 50))
            # Top-left highlight
            bd_draw.ellipse([cx - r + 1, cy - r + 1, cx - r + 4, cy - r + 4],
                            fill=(170, 152, 110))
            # Phillips cross
            bd_draw.line([cx - r + 2, cy, cx + r - 2, cy], fill=(20, 15, 8), width=2)
            bd_draw.line([cx, cy - r + 2, cx, cy + r - 2], fill=(20, 15, 8), width=2)
        screw(vent_x0 - 18, vent_cy)
        screw(vent_x1 + 18, vent_cy)

        # Power LED with glow halo
        led_cx = vent_x1 + 54
        led_cy = vent_cy
        if led_cx + 40 < bezel_x1 - 10:
            is_on = self.current_state == "locked"
            led_bright = (255, 160, 70) if is_on else (100, 60, 30)
            led_dim    = (200, 100, 40) if is_on else (70, 45, 20)
            # Recessed well
            bd_draw.rounded_rectangle(
                [led_cx - 10, led_cy - 10, led_cx + 10, led_cy + 10],
                radius=2, fill=(28, 18, 10),
            )
            # LED body
            bd_draw.rounded_rectangle(
                [led_cx - 7, led_cy - 7, led_cx + 7, led_cy + 7],
                radius=1, fill=led_dim,
            )
            # Halo glow (soft outer bloom if on)
            if is_on:
                halo = Image.new("RGBA", (60, 60), (0, 0, 0, 0))
                hd = ImageDraw.Draw(halo)
                for i in range(20, 0, -1):
                    a = int(8 * (i / 20))
                    hd.ellipse([30 - i, 30 - i, 30 + i, 30 + i],
                               fill=(255, 150, 60, a))
                halo = halo.filter(ImageFilter.GaussianBlur(radius=6))
                img.alpha_composite(halo, (led_cx - 30, led_cy - 30))
                # Bright center redrawn after halo
                bd_draw = ImageDraw.Draw(img)
                bd_draw.rounded_rectangle(
                    [led_cx - 5, led_cy - 5, led_cx + 5, led_cy + 5],
                    radius=1, fill=led_bright,
                )
            # "POWER" label
            try:
                from PIL import ImageFont
                font = ImageFont.load_default()
                bd_draw.text((led_cx - 16, led_cy + 12), "POWER",
                             fill=(50, 35, 20), font=font)
            except Exception:
                pass

        # Brand stamp
        try:
            from PIL import ImageFont
            font = ImageFont.load_default()
            bd_draw.text((bezel_x1 - 100, bezel_y1 - 14),
                         "ROBCO / ARKITEXE",
                         fill=(70, 50, 25), font=font)
        except Exception:
            pass

        # Rasterize and display on canvas
        self._bezel_pil_image = img  # keep ref so tk PhotoImage stays valid
        self._bezel_tk_image = ImageTk.PhotoImage(img)
        c = self.bezel_canvas
        self._bezel_image_id = c.create_image(0, 0, anchor="nw",
                                               image=self._bezel_tk_image)

    # ----- flat fallback (no Pillow) -----

    def _paint_bezel_flat(self, W, H,
                          bezel_x0, bezel_y0, bezel_x1, bezel_y1,
                          screen_x0, screen_y0, screen_x1, screen_y1) -> None:
        """Legacy flat-primitives paint. Used when Pillow isn't available."""
        c = self.bezel_canvas
        self._frame_ids.append(
            c.create_rectangle(0, 0, W, H, fill=self.BG, outline="")
        )
        self._draw_rounded_rect(
            bezel_x0, bezel_y0, bezel_x1, bezel_y1,
            r=18, fill=self.BEZEL, outline=self.BEZEL_SHADOW, width=2,
        )
        self._draw_rounded_rect(
            screen_x0, screen_y0, screen_x1, screen_y1,
            r=self.SCREEN_RADIUS, fill=self.SCREEN_BG, outline=self.GREEN_DIM,
            width=1,
        )
        for y in range(screen_y0 + 4, screen_y1 - 4, 3):
            sid = c.create_line(
                screen_x0 + 6, y, screen_x1 - 6, y,
                fill=self.SCANLINE, width=1,
            )
            self._scanline_ids.append(sid)

    def _draw_rounded_rect(self, x0, y0, x1, y1, r=10,
                            fill="", outline="", width=1) -> None:
        """Approximate a rounded rectangle on a Canvas using a polygon+arcs."""
        c = self.bezel_canvas
        # Body polygon (octagonal approximation for the fill)
        pts = [
            x0 + r, y0,
            x1 - r, y0,
            x1,     y0 + r,
            x1,     y1 - r,
            x1 - r, y1,
            x0 + r, y1,
            x0,     y1 - r,
            x0,     y0 + r,
        ]
        self._frame_ids.append(c.create_polygon(
            pts, fill=fill, outline="", smooth=False))
        # Outline: four straight edges + four corner arcs
        if outline and width > 0:
            self._frame_ids.append(c.create_arc(
                x0, y0, x0 + 2 * r, y0 + 2 * r, start=90, extent=90,
                style="arc", outline=outline, width=width))
            self._frame_ids.append(c.create_arc(
                x1 - 2 * r, y0, x1, y0 + 2 * r, start=0, extent=90,
                style="arc", outline=outline, width=width))
            self._frame_ids.append(c.create_arc(
                x0, y1 - 2 * r, x0 + 2 * r, y1, start=180, extent=90,
                style="arc", outline=outline, width=width))
            self._frame_ids.append(c.create_arc(
                x1 - 2 * r, y1 - 2 * r, x1, y1, start=270, extent=90,
                style="arc", outline=outline, width=width))
            self._frame_ids.append(c.create_line(
                x0 + r, y0, x1 - r, y0, fill=outline, width=width))
            self._frame_ids.append(c.create_line(
                x0 + r, y1, x1 - r, y1, fill=outline, width=width))
            self._frame_ids.append(c.create_line(
                x0, y0 + r, x0, y1 - r, fill=outline, width=width))
            self._frame_ids.append(c.create_line(
                x1, y0 + r, x1, y1 - r, fill=outline, width=width))

    # ---- event handlers ----

    def _on_update_click(self) -> None:
        self.updater.start_update()

    def _on_stats_toggle(self) -> None:
        """Show/hide the live stats panel."""
        if self.stats_panel_visible:
            self.stats_frame.pack_forget()
            self.stats_panel_visible = False
            self.stats_btn.configure(
                text="[ LIVE STATS: OFF ]",
                fg=self.GREEN_DIM,
                highlightbackground=self.GREEN_DIM,
            )
        else:
            self.stats_frame.pack(
                fill=tk.X, padx=10, pady=2,
                before=self.history_heading,
            )
            self.stats_panel_visible = True
            self.stats_btn.configure(
                text="[ LIVE STATS: ON ]",
                fg=self.GREEN_BRIGHT,
                highlightbackground=self.GREEN_BRIGHT,
            )
            self._refresh_live_stats()

    def _on_legend_toggle(self) -> None:
        """Show/hide the endpoint-category legend panel."""
        if self.legend_visible:
            self.legend_frame.pack_forget()
            self.legend_visible = False
            self.legend_btn.configure(
                text="[ LEGEND: OFF ]",
                fg=self.GREEN_DIM,
                highlightbackground=self.GREEN_DIM,
            )
        else:
            self.legend_frame.pack(
                fill=tk.X, padx=10, pady=2,
                before=self.history_heading,
            )
            self.legend_visible = True
            self.legend_btn.configure(
                text="[ LEGEND: ON ]",
                fg=self.GREEN_BRIGHT,
                highlightbackground=self.GREEN_BRIGHT,
            )

    def _on_log_attempts_toggle(self) -> None:
        """Toggle allocation-attempt logging on/off."""
        self.log_allocation_attempts = not self.log_allocation_attempts
        self.match_logger.log_allocation_attempts = self.log_allocation_attempts
        if self.log_allocation_attempts:
            self.log_attempts_btn.configure(
                text="[ LOG ATTEMPTS: ON ]",
                fg=self.GREEN,
                highlightbackground=self.GREEN,
            )
        else:
            self.log_attempts_btn.configure(
                text="[ LOG ATTEMPTS: OFF ]",
                fg=self.GREEN_DIM,
                highlightbackground=self.GREEN_DIM,
            )

    def _process_queue(self) -> None:
        try:
            while True:
                msg = self.ui_queue.get_nowait()
                self._handle_message(msg)
        except queue.Empty:
            pass
        self.root.after(150, self._process_queue)

    def _handle_message(self, msg: dict) -> None:
        t = msg.get("type")

        if t == "halo_status":
            if msg.get("running"):
                self.halo_running = True
                self.current_state = "scanning"
            else:
                self.halo_running = False
                self.current_state = "init"
                self.current_server = None
            self._refresh_status()

        elif t == "searching":
            self.current_state = "searching"
            self.current_server = None
            self._refresh_status()

        elif t == "no_server":
            self.current_state = "scanning"
            self.current_server = None
            self._refresh_status()

        elif t == "server":
            # A CONFIRMED match just started. This has already passed the
            # 15s / 5 PPS threshold, so it's a real match -- not a false
            # positive queue-allocation attempt.
            self.current_state = "locked"
            self.current_server = msg
            # Pick a random emoji for this match
            emoji_path = self.resources.random_emoji()
            self.match_history.appendleft({
                "match_number": msg.get("match_number", "?"),
                "display": msg.get("display", "Unknown"),
                "azure": msg.get("azure", ""),
                "ip": msg.get("ip", ""),
                "port": msg.get("port", 0),
                "protocol": msg.get("protocol", ""),
                "started_at": datetime.now().strftime("%I:%M:%S %p"),
                "emoji_path": emoji_path,
                "ended": False,
                "duration_sec": None,
                "is_short": False,
                "peers": [],  # v15: filled in at match_ended
            })
            # Trigger teabag GIF on match start
            self._play_gif("teabag", "MATCH ACQUIRED", duration_sec=8.0)
            self._refresh_status()
            self._redraw_history()

        elif t == "match_ended":
            # Match just ended cleanly. Mark it in history and decide if it
            # was short (rage-quit or dc) for the rage GIF trigger.
            num = msg.get("match_number")
            dur = float(msg.get("duration_sec") or 0.0)
            is_short = dur < 60.0
            peers = msg.get("peers") or []
            # Flip ended flag on matching record
            for rec in self.match_history:
                if rec.get("match_number") == num:
                    rec["ended"] = True
                    rec["duration_sec"] = dur
                    rec["is_short"] = is_short
                    rec["peers"] = peers
                    break
            if is_short:
                self._play_gif("rage", "SHORT MATCH -- RAGE?", duration_sec=6.0)
            self._redraw_history()

        elif t == "vpn_status":
            self.vpn_name = msg.get("name")
            self._refresh_status()

        elif t == "udp_status":
            self.udp_status_text = msg.get("text", "")
            self.udp_status_lbl.configure(text=self.udp_status_text)

        elif t == "update_status":
            self.update_status_text = msg.get("text", "")
            self.update_status_lbl.configure(text=self.update_status_text)

        elif t == "queue_info":
            self.queue_info = msg
            self._refresh_queue_info()

        elif t == "live_stats":
            self.live_stats = msg
            if self.stats_panel_visible:
                self._refresh_live_stats()

    def _refresh_status(self) -> None:
        # Title is a Canvas with baked-in glow layers -- we don't dim it
        # by state anymore (the halo effect reads too weird when the
        # foreground alpha-shifts).

        # VPN label
        if self.vpn_name:
            self.vpn_lbl.configure(
                text=f"[ VPN: {self.vpn_name} ]",
                fg=self.GREEN_BRIGHT,
            )
        else:
            self.vpn_lbl.configure(
                text="[ VPN: none ]",
                fg=self.GREEN_DIM,
            )

        # Status block
        if self.current_state == "init":
            self.status_lbl.configure(text="[  SCANNING FOR HALO  ]",
                                       fg=self.GREEN_DIM)
            self.location_lbl.configure(text="")
            self.endpoint_lbl.configure(text="")
        elif self.current_state == "scanning":
            self.status_lbl.configure(text="[  HALO ONLINE - NO ACTIVE MATCH  ]",
                                       fg=self.GREEN)
            self.location_lbl.configure(text="")
            self.endpoint_lbl.configure(text="")
        elif self.current_state == "searching":
            self.status_lbl.configure(text="[  MATCHMAKING - QoS PROBES ACTIVE  ]",
                                       fg=self.GREEN_BRIGHT)
            self.location_lbl.configure(text="")
            self.endpoint_lbl.configure(text="")
        elif self.current_state == "locked" and self.current_server:
            s = self.current_server
            self.status_lbl.configure(text="[  SERVER LOCKED  ]",
                                       fg=self.GREEN_BRIGHT)
            self.location_lbl.configure(
                text=f"{(s.get('display') or 'Unknown').upper()}",
                fg=self.GREEN_BRIGHT,
            )
            self.endpoint_lbl.configure(
                text=f"// {(s.get('azure') or '').upper()} // "
                     f"{s.get('ip','')}:{s.get('port','?')}/"
                     f"{s.get('protocol','?')}",
                fg=self.GREEN_DIM,
            )

        self._refresh_queue_info()

    def _redraw_history(self) -> None:
        """
        Redraw the match history panel. Each entry:
          MATCH N [emoji]  LOCATION  (region)  @time   duration
             ip:port/proto  LOCKED
             (peer ips listed as PEER)
             "random halo quote"
        Quotes re-roll on every redraw.
        """
        self.history_text.configure(state=tk.NORMAL)
        self.history_text.delete("1.0", tk.END)

        if not self.match_history:
            self.history_text.insert(
                tk.END,
                "  ( no confirmed matches yet )\n"
                "  ( matches only count once they sustain 5+ PPS for 15+ seconds )\n"
                "  ( short-lived queue allocation attempts go in the log, not here )\n",
                "empty",
            )
            self.history_text.configure(state=tk.DISABLED)
            return

        for m in self.match_history:
            num = m["match_number"]
            loc = (m["display"] or "Unknown").upper()
            az = (m["azure"] or "").upper()
            started = m.get("started_at", "")
            ended = m.get("ended", False)
            dur = m.get("duration_sec")
            is_short = m.get("is_short", False)

            # Label: CONFIRMED matches display "MATCH N". Short matches get a
            # dimmer sub-label so you can tell at a glance which were real games
            # and which were just rage-quits / disconnects.
            self.history_text.insert(tk.END, f" MATCH {num:>3}  ", "match_label")

            # Inline emoji (if Pillow loaded one)
            emoji_path = m.get("emoji_path")
            if emoji_path is not None:
                photo = self.resources.get_emoji_photo(emoji_path)
                if photo is not None:
                    self.history_text.image_create(tk.END, image=photo)
                    # Hold ref on the Text widget to prevent GC
                    if not hasattr(self.history_text, "_img_refs"):
                        self.history_text._img_refs = []  # type: ignore[attr-defined]
                    self.history_text._img_refs.append(photo)  # type: ignore
                    self.history_text.insert(tk.END, "  ", "details")

            self.history_text.insert(tk.END, f"{loc}", "location")

            # Region + start time + (optional) duration tag
            tail = f"   ({az})  @{started}"
            self.history_text.insert(tk.END, tail, "details")
            if dur is not None:
                m_min = int(dur // 60); m_sec = int(dur % 60)
                self.history_text.insert(tk.END,
                                          f"   duration {m_min}m {m_sec:02d}s  ",
                                          "details")
                if is_short:
                    # A real match that ended quickly (< 60s). NOT an
                    # allocation attempt -- those never reach the history.
                    # Could be a back-out, quick DC, rage quit, etc.
                    self.history_text.insert(tk.END, "[QUICK MATCH]", "short_tag")
                else:
                    self.history_text.insert(tk.END, "[ENDED]", "ended_tag")
            elif not ended:
                self.history_text.insert(tk.END, "   ", "details")
                self.history_text.insert(tk.END, "[IN PROGRESS]", "live_tag")
            self.history_text.insert(tk.END, "\n", "details")

            endpoint_line = (f"           {m['ip']}:{m['port']}/"
                             f"{m['protocol']}  <-- LOCKED\n")
            self.history_text.insert(tk.END, endpoint_line, "details")

            # Peer endpoints (other UDPs on the game-server range that were
            # seen during this match but were NOT the locked server). For
            # the CURRENT (open) match we pull live from the tracker; for
            # past matches we use the peers list captured at match_ended.
            if (self.current_server is not None
                    and self.current_server.get("match_number") == num
                    and not ended):
                peers = self._collect_peer_endpoints()
                for peer_ip, peer_port, peer_proto, peer_region in peers:
                    peer_line = (f"           {peer_ip}:{peer_port}/{peer_proto}"
                                 f"  ({peer_region})  -- PEER (not match server)\n")
                    self.history_text.insert(tk.END, peer_line, "peer")
            else:
                # Past match: pull peers from stored record
                for p in m.get("peers") or []:
                    peer_line = (f"           {p['ip']}:{p['port']}/"
                                 f"{p['protocol']}  ({p.get('region','')})"
                                 f"  -- PEER (not match server)\n")
                    self.history_text.insert(tk.END, peer_line, "peer")

            # Random quote per match, re-rolled on every redraw
            quote = self.resources.random_quote()
            if quote:
                self.history_text.insert(tk.END, f'  " {quote} "\n', "quote")
            self.history_text.insert(tk.END,
                                      "  " + "-" * 48 + "\n\n", "separator")

        self.history_text.configure(state=tk.DISABLED)

    def _collect_peer_endpoints(self) -> list:
        """
        Pull non-LOCKED GAME_SERVER endpoints from the current open match
        record. Returns list of (ip, port, proto, region) tuples.
        """
        out = []
        try:
            current = self.match_logger.current_match
            if current is None:
                return out
            locked = (current.server_ip, current.server_port,
                      current.server_protocol)
            for ip, port, proto, kind in sorted(current.endpoints_observed):
                if kind != KIND_GAME_SERVER:
                    continue
                if (ip, port, proto) == locked:
                    continue
                _, region = ip_to_region(ip)
                out.append((ip, port, proto, region or "unknown region"))
        except Exception:
            pass
        return out

    def _refresh_queue_info(self) -> None:
        if self.queue_info is None or not self.queue_info.get("in_queue"):
            self.queue_info_lbl.configure(text="")
            return
        if self.current_state == "locked":
            self.queue_info_lbl.configure(text="")
            return

        age = self.queue_info.get("age_str", "0s")
        attempts = self.queue_info.get("attempts", 0)
        regions = self.queue_info.get("regions", 0)
        health = self.queue_info.get("health")

        health_color = {
            QueueHealthTracker.HEALTH_HOT:       self.GREEN_BRIGHT,
            QueueHealthTracker.HEALTH_WARM:      self.GREEN,
            QueueHealthTracker.HEALTH_COLD:      self.GREEN_DIM,
            QueueHealthTracker.HEALTH_DESERTED:  self.RED_WARN,
        }.get(health, self.GREEN)

        health_tag = health if health else "?"
        attempts_str = f"{attempts} attempt" + ("s" if attempts != 1 else "")
        regions_str = f"{regions} region" + ("s" if regions != 1 else "")

        text = (f"QUEUE: {health_tag}   TIME: {age}   "
                f"{attempts_str}   {regions_str} probed")
        self.queue_info_lbl.configure(text=text, fg=health_color)

    def _refresh_live_stats(self) -> None:
        if not self.stats_panel_visible:
            return
        if self.live_stats is None or not self.current_server:
            self.stats_text_lbl.configure(
                text=" (no active connection)",
                fg=self.GREEN_DIM,
            )
            return

        s = self.live_stats
        cs = self.current_server

        def fmt_bytes(n) -> str:
            if n is None:
                return "?"
            n = float(n)
            for unit in ("B", "KB", "MB", "GB"):
                if n < 1024:
                    return f"{n:.1f}{unit}"
                n /= 1024
            return f"{n:.1f}TB"

        def fmt_rtt(v) -> str:
            return f"{v:.1f}ms" if v is not None else "--"

        pps_line = (f" PPS:        {s.get('pps_total', 0):>6.1f}   "
                    f"(down {s.get('pps_in', 0):>5.1f}  "
                    f"up {s.get('pps_out', 0):>5.1f})")
        bps_line = (f" Bandwidth:  {fmt_bytes(s.get('bps', 0)):>7}/s   "
                    f"(down {fmt_bytes(s.get('bytes_in',0) // max(s.get('age_sec',1),1))} "
                    f"up {fmt_bytes(s.get('bytes_out',0) // max(s.get('age_sec',1),1))})")
        rtt_line = (f" RTT:        avg {fmt_rtt(s.get('avg_rtt'))}   "
                    f"min {fmt_rtt(s.get('min_rtt'))}   "
                    f"max {fmt_rtt(s.get('max_rtt'))}   "
                    f"jitter {fmt_rtt(s.get('jitter'))}")
        pkts_line = (f" Packets:    {s.get('total_packets',0):>6,}   "
                     f"(in {s.get('packets_in',0):>5,}   "
                     f"out {s.get('packets_out',0):>5,})")
        bytes_line = (f" Total:      {fmt_bytes(s.get('total_bytes',0)):>7}   "
                      f"(in {fmt_bytes(s.get('bytes_in',0))}  "
                      f"out {fmt_bytes(s.get('bytes_out',0))})")
        size_line = f" Pkt size:   avg {s.get('avg_packet_size', 0) or 0:.0f} B  " \
                    f"({s.get('size_hist', '--')})"
        age_sec = s.get('age_sec', 0)
        am, asec = divmod(int(age_sec), 60)
        age_line = (f" Server:     {cs.get('ip')}:{cs.get('port')}/{cs.get('protocol')}  "
                    f"age {am}m {asec:02d}s")

        block = "\n".join([age_line, pps_line, bps_line, rtt_line,
                           pkts_line, bytes_line, size_line])
        self.stats_text_lbl.configure(text=block, fg=self.GREEN)

    # ---- animation ----

    def _play_gif(self, name: str, caption: str, duration_sec: float) -> None:
        """v15: Both GIFs always animate -- this now just flashes a caption.

        v14 used this to switch a single gif slot between teabag / rage. v15
        shows both at all times so the "which gif to show" concept is gone.
        The caption still gets set temporarily to reflect what just happened
        (e.g. "MATCH STARTED -- TEABAG!" on match start, "RAGE QUIT!" on a
        short match), then fades back to standby.
        """
        self._gif_caption_until = time.time() + duration_sec
        try:
            self.gif_caption_lbl.configure(text=caption, fg=self.GREEN_BRIGHT)
        except tk.TclError:
            return

    def _gif_tick(self) -> None:
        """Advance both GIFs independently every tick.

        Each gif has its own frame index and per-frame delay. We use the
        minimum of the two delays as the next tick so both stay smooth.
        """
        # Fade the caption back to standby if its time is up
        if getattr(self, "_gif_caption_until", 0.0) and time.time() > self._gif_caption_until:
            try:
                self.gif_caption_lbl.configure(text="[ standing by ]", fg=self.GREEN_DIM)
            except tk.TclError:
                return
            self._gif_caption_until = 0.0

        next_delay = 120

        # Left = teabag, right = rage
        for slot_name, widget, idx_attr in (
                ("teabag", self.gif_label_left, "_gif_idx_left"),
                ("rage",   self.gif_label_right, "_gif_idx_right")):
            if slot_name not in self.resources.gif_frames:
                continue
            frames = self.resources.gif_frames[slot_name]
            delays = self.resources.gif_delays[slot_name]
            if not frames:
                continue
            idx = getattr(self, idx_attr, 0) % len(frames)
            try:
                widget.configure(image=frames[idx], text="")
                widget.image = frames[idx]  # keep ref
            except tk.TclError:
                return
            setattr(self, idx_attr, idx + 1)
            this_delay = delays[idx] if idx < len(delays) else 120
            next_delay = min(next_delay, max(40, int(this_delay)))

        try:
            self.root.after(next_delay, self._gif_tick)
        except tk.TclError:
            return

    def _blink_tick(self) -> None:
        self._blink_state = not self._blink_state
        try:
            if self.current_state == "locked":
                self.status_lbl.configure(fg=self.GREEN_BRIGHT)
            elif self.current_state == "searching":
                self.status_lbl.configure(
                    fg=self.GREEN_BRIGHT if self._blink_state else self.GREEN_DIM)
            elif self.current_state == "scanning":
                self.status_lbl.configure(
                    fg=self.GREEN if self._blink_state else self.GREEN_DIM)
            else:
                self.status_lbl.configure(
                    fg=self.GREEN_DIM if self._blink_state else self.GREEN_FAINT)
        except tk.TclError:
            return
        self.root.after(700, self._blink_tick)

    def _on_close(self) -> None:
        log.info("Window closing; stopping worker...")
        try:
            self.worker.stop()
        except Exception:
            pass
        try:
            self.root.destroy()
        except Exception:
            pass

    def run(self) -> None:
        try:
            self.root.mainloop()
        finally:
            self.worker.stop()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    try:
        gui = ArtemisGUI()
        gui.run()
    except KeyboardInterrupt:
        pass
    return 0


# Back-compat alias: old scripts / .spec files may reference PipBoyGUI
PipBoyGUI = ArtemisGUI


if __name__ == "__main__":
    sys.exit(main())
