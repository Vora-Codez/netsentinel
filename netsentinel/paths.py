"""Where things live."""
import os
import sys
from pathlib import Path


def frozen() -> bool:
    """True when running from the single-file executable built by PyInstaller."""
    return bool(getattr(sys, "frozen", False))


def web_dir() -> Path:
    # PyInstaller unpacks bundled files to a temp folder (sys._MEIPASS).
    if frozen():
        return Path(sys._MEIPASS) / "netsentinel" / "web"
    return Path(__file__).resolve().parent / "web"


def data_dir() -> Path:
    """Writable folder for the database, settings, secret key and logs.
    $NETSENTINEL_HOME, else ./data (Docker mounts a volume at /data).
    The single-file exe keeps it next to the exe, because its own folder is wiped on exit."""
    default = Path(sys.executable).resolve().parent / "NetSentinel-data" if frozen() else "data"
    base = Path(os.environ.get("NETSENTINEL_HOME") or default).resolve()
    base.mkdir(parents=True, exist_ok=True)
    return base


def can_capture() -> bool:
    """True if this process may open raw sockets (root, Administrator, or CAP_NET_RAW)."""
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        if os.geteuid() == 0:
            return True
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    return bool(int(line.split()[1], 16) & (1 << 13))   # CAP_NET_RAW
    except Exception:
        pass
    return False
