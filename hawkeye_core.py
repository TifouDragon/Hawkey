import re
import json
import time
import math
import shutil
import hashlib
import ipaddress
import subprocess
import uuid
import os
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from enum import Enum

import psutil

try:
    import winreg
except ImportError:
    winreg = None


class ThreatLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Finding:
    timestamp: str
    path: str
    name: str
    level: ThreatLevel
    category: str
    score: int
    reasons: list
    sha256: str | None = None
    process_pids: list[int] | None = None
    remote_ips: list[str] | None = None
    confidence: str | None = None


POWERSHELL_RED_FLAGS = [
    "iex", "invoke-expression",
    "downloadstring", "invoke-webrequest", "iwr", "wget", "curl",
    "frombase64string", "encodedcommand",
    "add-mppreference", "set-mppreference",
    "bypass", "hidden", "nop", "noni",
    "new-object net.webclient",
    "start-process", "rundll32",
]

PS_PATTERNS = [
    re.compile(r"encodedcommand\s+[a-z0-9+/=]{20,}", re.I),
    re.compile(r"frombase64string\s*\(", re.I),
    re.compile(r"new-object\s+net\.webclient", re.I),
    re.compile(r"invoke-webrequest|downloadstring", re.I),
]

SUSPICIOUS_DIR_MARKERS = ["\\temp\\", "\\appdata\\", "\\downloads\\", "\\programdata\\"]
SAFE_DIR_MARKERS = ["\\windows\\", "\\program files\\", "\\program files (x86)\\"]

SUSPICIOUS_PORTS = {
    4444, 1337, 6667, 5555, 9001, 9002, 9050, 1080, 12345
}

RISKY_SERVICE_PORTS = {
    21, 23, 25, 69, 135, 137, 139, 445, 3389
}

SUSPICIOUS_PROCESS_NAMES = {
    "powershell.exe", "wscript.exe", "cscript.exe", "cmd.exe", "rundll32.exe", "mshta.exe"
}


def sha256_file(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def file_entropy(path: Path, max_bytes: int = 256_000) -> float | None:
    try:
        data = path.read_bytes()[:max_bytes]
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        ent = 0.0
        n = len(data)
        for c in freq:
            if c:
                p = c / n
                ent -= p * math.log2(p)
        return ent
    except Exception:
        return None


def scan_script_content(path: Path) -> tuple[int, list]:
    score = 0
    reasons = []
    try:
        content = path.read_text(errors="ignore").lower()

        for flag in POWERSHELL_RED_FLAGS:
            if flag in content:
                score += 2
                reasons.append(f"string:{flag}")

        for pat in PS_PATTERNS:
            if pat.search(content):
                score += 4
                reasons.append(f"pattern:{pat.pattern}")

        # batch obfuscation
        if len(re.findall(r"\^[a-z]", content)) > 20:
            score += 3
            reasons.append("obfuscation:caret")

        # base64-ish blobs
        if re.search(r"[A-Za-z0-9+/=]{200,}", content):
            score += 3
            reasons.append("blob:base64ish")

    except Exception:
        pass

    return score, reasons


def path_risk_score(path: Path) -> tuple[int, list]:
    score = 0
    reasons = []
    p = str(path).lower()

    for m in SUSPICIOUS_DIR_MARKERS:
        if m in p:
            score += 2
            reasons.append(f"dir:{m.strip('\\')}")
            break

    for m in SAFE_DIR_MARKERS:
        if m in p:
            score -= 1
            reasons.append(f"dir:safe:{m.strip('\\')}")
            break

    ext = path.suffix.lower()
    if ext in [".exe", ".dll", ".scr"]:
        score += 2
        reasons.append(f"ext:{ext}")
    elif ext in [".ps1", ".bat", ".cmd", ".vbs", ".js"]:
        score += 2
        reasons.append(f"ext:{ext}")
    elif ext in [".zip", ".7z", ".rar"]:
        score += 1
        reasons.append(f"ext:{ext}")

    return score, reasons


def level_from_score(score: int) -> ThreatLevel:
    score = max(0, min(score, 20))
    if score >= 12:
        return ThreatLevel.CRITICAL
    if score >= 8:
        return ThreatLevel.HIGH
    if score >= 4:
        return ThreatLevel.MEDIUM
    return ThreatLevel.LOW


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global
    except Exception:
        return False


def normalize_port_list(ports) -> set[int]:
    out = set()
    if not ports:
        return out
    for p in ports:
        try:
            out.add(int(str(p).strip()))
        except Exception:
            continue
    return out


def normalize_ip_list(ips) -> set[str]:
    out = set()
    if not ips:
        return out
    for ip in ips:
        s = str(ip).strip()
        if s:
            out.add(s)
    return out


def is_file_signed_windows(path: Path) -> bool | None:
    try:
        import ctypes
        from ctypes import wintypes
    except Exception:
        return None

    if not path.exists():
        return None

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", wintypes.BYTE * 8),
        ]

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pcwszFilePath", wintypes.LPCWSTR),
            ("hFile", wintypes.HANDLE),
            ("pgKnownSubject", ctypes.POINTER(GUID)),
        ]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", wintypes.DWORD),
            ("fdwRevocationChecks", wintypes.DWORD),
            ("dwUnionChoice", wintypes.DWORD),
            ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
            ("dwStateAction", wintypes.DWORD),
            ("hWVTStateData", wintypes.HANDLE),
            ("pwszURLReference", wintypes.LPCWSTR),
            ("dwProvFlags", wintypes.DWORD),
            ("dwUIContext", wintypes.DWORD),
        ]

    WTD_UI_NONE = 2
    WTD_REVOKE_NONE = 0
    WTD_CHOICE_FILE = 1
    WTD_STATEACTION_VERIFY = 1
    WTD_STATEACTION_CLOSE = 2
    WTD_SAFER_FLAG = 0x00000100

    action = GUID(
        0x00AAC56B,
        0xCD44,
        0x11d0,
        (wintypes.BYTE * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
    )

    file_info = WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    file_info.pcwszFilePath = str(path)
    file_info.hFile = None
    file_info.pgKnownSubject = None

    trust_data = WINTRUST_DATA()
    trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    trust_data.pPolicyCallbackData = None
    trust_data.pSIPClientData = None
    trust_data.dwUIChoice = WTD_UI_NONE
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE
    trust_data.dwUnionChoice = WTD_CHOICE_FILE
    trust_data.pFile = ctypes.pointer(file_info)
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY
    trust_data.hWVTStateData = None
    trust_data.pwszURLReference = None
    trust_data.dwProvFlags = WTD_SAFER_FLAG
    trust_data.dwUIContext = 0

    wintrust = ctypes.windll.wintrust
    result = wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(trust_data))
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE
    wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(trust_data))

    return result == 0


def analyze_connection(remote_ip: str, remote_port: int, local_port: int | None,
                       process_name: str | None, seen_ips: set[str],
                       allowlist_ips: set[str], allowlist_ports: set[int]) -> dict | None:
    if remote_ip in allowlist_ips or remote_port in allowlist_ports:
        return None

    score = 0
    reasons = []

    if remote_port in SUSPICIOUS_PORTS:
        score += 4
        reasons.append(f"port:suspicious:{remote_port}")

    if remote_port in RISKY_SERVICE_PORTS:
        score += 2
        reasons.append(f"port:risky:{remote_port}")

    if is_public_ip(remote_ip):
        if remote_ip not in seen_ips:
            score += 1
            reasons.append("ip:new_public")
    else:
        reasons.append("ip:private_or_reserved")

    if process_name and process_name.lower() in SUSPICIOUS_PROCESS_NAMES:
        score += 2
        reasons.append(f"proc:{process_name}")

    if score <= 0:
        return None

    return {
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "local_port": local_port,
        "process_name": process_name,
        "score": score,
        "reasons": reasons[:10],
    }


def find_processes_by_exe(target_path: Path) -> list[int]:
    pids = []
    try:
        for proc in psutil.process_iter(["pid", "exe"]):
            exe = proc.info.get("exe")
            if not exe:
                continue
            try:
                if Path(exe) == target_path:
                    pids.append(proc.info["pid"])
            except Exception:
                continue
    except Exception:
        pass
    return pids


def network_peers_by_pid(pid: int) -> list[str]:
    ips = []
    try:
        p = psutil.Process(pid)
        for c in p.net_connections(kind="inet"):
            if c.raddr and c.raddr.ip:
                ip = c.raddr.ip
                if ip not in ips:
                    ips.append(ip)
    except Exception:
        pass
    return ips


class HawkEyeCore:
    def __init__(self, quarantine_dir: str = "hawkeye_quarantine", log_path: str = "hawkeye_events.jsonl"):
        self.quarantine_dir = Path(quarantine_dir)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = Path(log_path)
        self._hash_cache = {}
        self._entropy_cache = {}
        self._log_max_bytes = 20 * 1024 * 1024

    def log(self, event: dict):
        try:
            if "event_id" not in event:
                event["event_id"] = str(uuid.uuid4())
            try:
                if self.log_path.exists() and self.log_path.stat().st_size > self._log_max_bytes:
                    backup = self.log_path.with_suffix(self.log_path.suffix + ".1")
                    if backup.exists():
                        backup.unlink(missing_ok=True)
                    os.replace(self.log_path, backup)
            except Exception:
                pass
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def _file_sig(self, path: Path):
        st = path.stat()
        return (str(path), st.st_size, int(st.st_mtime))

    def sha256_cached(self, path: Path) -> str | None:
        try:
            sig = self._file_sig(path)
            if sig in self._hash_cache:
                return self._hash_cache[sig]
            h = sha256_file(path)
            if h:
                self._hash_cache[sig] = h
            return h
        except Exception:
            return None

    def entropy_cached(self, path: Path) -> float | None:
        try:
            sig = self._file_sig(path)
            if sig in self._entropy_cache:
                return self._entropy_cache[sig]
            e = file_entropy(path)
            if e is not None:
                self._entropy_cache[sig] = e
            return e
        except Exception:
            return None

    def analyze_file(self, path: Path) -> Finding | None:
        score, reasons = path_risk_score(path)

        ext = path.suffix.lower()
        if ext in [".ps1", ".bat", ".cmd", ".vbs", ".js"]:
            s, r = scan_script_content(path)
            score += s
            reasons += r

        if ext in [".exe", ".dll", ".scr"]:
            ent = self.entropy_cached(path)
            if ent is not None and ent >= 7.5:
                score += 3
                reasons.append(f"entropy:{ent:.2f}")

            signed = is_file_signed_windows(path)
            if signed is True:
                score -= 2
                reasons.append("signed:trusted")
            elif signed is False:
                score += 1
                reasons.append("signed:missing")

        pids = find_processes_by_exe(path)
        remote_ips = []
        if pids:
            score += 1
            reasons.append("running:process")
            for pid in pids:
                remote_ips += network_peers_by_pid(pid)
            remote_ips = sorted(set(remote_ips))
            if remote_ips:
                score += 2
                reasons.append("network:remote_peers")

        level = level_from_score(score)
        if level == ThreatLevel.LOW:
            return None
        confidence = "low"
        if score >= 12:
            confidence = "high"
        elif score >= 8:
            confidence = "medium"

        return Finding(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            path=str(path),
            name=path.name,
            level=level,
            category="file",
            score=score,
            reasons=reasons[:25],
            sha256=self.sha256_cached(path),
            process_pids=pids if pids else None,
            remote_ips=remote_ips if remote_ips else None,
            confidence=confidence,
        )

    def _should_skip(self, path: Path, exclude_paths: list[str],
                     exclude_exts: set[str], exclude_hashes: set[str]) -> bool:
        try:
            p = str(path).lower()
            for base in exclude_paths:
                if p.startswith(base):
                    return True
        except Exception:
            pass

        if exclude_exts:
            if path.suffix.lower() in exclude_exts:
                return True

        if exclude_hashes:
            h = self.sha256_cached(path)
            if h and h.lower() in exclude_hashes:
                return True

        return False

    def scan_path(self, root: str, max_files: int | None = None,
                  exclude_paths: list[str] | None = None,
                  exclude_exts: set[str] | None = None,
                  exclude_hashes: set[str] | None = None,
                  stop_event=None,
                  pause_event=None,
                  progress_callback=None,
                  log_scanned: bool = False):
        findings = []
        root_path = Path(root)
        seen = 0
        ex_paths = exclude_paths or []
        ex_exts = exclude_exts or set()
        ex_hashes = exclude_hashes or set()

        for p in root_path.rglob("*"):
            if stop_event is not None and stop_event.is_set():
                break
            if pause_event is not None and pause_event.is_set():
                while pause_event.is_set():
                    time.sleep(0.1)
                    if stop_event is not None and stop_event.is_set():
                        break
            if max_files and seen >= max_files:
                break
            if not p.is_file():
                continue
            if self._should_skip(p, ex_paths, ex_exts, ex_hashes):
                continue
            seen += 1
            if log_scanned:
                try:
                    self.log({"type": "scanned", "path": str(p), "size": p.stat().st_size})
                except Exception:
                    pass
            if progress_callback:
                try:
                    progress_callback(seen)
                except Exception:
                    pass

            f = self.analyze_file(p)
            if f:
                findings.append(f)
                self.log({"type": "finding", **asdict(f), "level": f.level.name})

        return findings

    def list_quarantine_items(self) -> list[dict]:
        items = []
        for meta in self.quarantine_dir.rglob("*.json"):
            try:
                data = json.loads(meta.read_text(encoding="utf-8"))
                data["_meta_path"] = str(meta)
                items.append(data)
            except Exception:
                continue
        return items

    def restore_quarantine(self, meta_path: str) -> dict:
        try:
            meta = Path(meta_path)
            data = json.loads(meta.read_text(encoding="utf-8"))
            quarantined = Path(data.get("quarantined_to", ""))
            original = Path(data.get("path", ""))
            if not quarantined.exists():
                return {"ok": False, "error": "quarantined_missing"}
            if original.exists():
                return {"ok": False, "error": "original_exists"}
            original.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(quarantined), str(original))
            meta.unlink(missing_ok=True)
            self.log({"type": "restore", "src": str(quarantined), "dst": str(original)})
            return {"ok": True, "restored_to": str(original)}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def delete_quarantine(self, meta_path: str) -> dict:
        try:
            meta = Path(meta_path)
            data = json.loads(meta.read_text(encoding="utf-8"))
            quarantined = Path(data.get("quarantined_to", ""))
            if quarantined.exists():
                quarantined.unlink(missing_ok=True)
            meta.unlink(missing_ok=True)
            self.log({"type": "quarantine_delete", "src": str(quarantined)})
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def quarantine(self, finding: Finding, kill_process: bool = True) -> dict:
        src = Path(finding.path)
        if not src.exists():
            return {"ok": False, "error": "file_missing"}

        if kill_process and finding.process_pids:
            for pid in finding.process_pids:
                try:
                    psutil.Process(pid).kill()
                except Exception:
                    pass

        ts = int(time.time())
        dest_dir = self.quarantine_dir / finding.level.name.lower()
        dest_dir.mkdir(parents=True, exist_ok=True)

        dest_file = dest_dir / f"{ts}_{src.name}"
        meta_file = dest_dir / f"{ts}_{src.name}.json"

        try:
            shutil.move(str(src), str(dest_file))
            with open(meta_file, "w", encoding="utf-8") as f:
                json.dump({**asdict(finding), "level": finding.level.name, "quarantined_to": str(dest_file)},
                          f, ensure_ascii=False, indent=2)
            self.log({"type": "quarantine", "src": finding.path, "dst": str(dest_file), "level": finding.level.name})
            return {"ok": True, "dst": str(dest_file), "meta": str(meta_file)}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def scan_run_keys(self) -> list[dict]:
        if winreg is None:
            return []

        results = []
        keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ]

        for hive, subkey in keys:
            try:
                k = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(k, i)
                        i += 1
                        val = str(value)
                        lower = val.lower()
                        score = 0
                        reasons = []

                        if any(m in lower for m in SUSPICIOUS_DIR_MARKERS):
                            score += 4
                            reasons.append("runkey:suspicious_path")

                        if "powershell" in lower and ("-enc" in lower or "encodedcommand" in lower):
                            score += 6
                            reasons.append("runkey:powershell_encoded")

                        if score >= 4:
                            results.append({
                                "hive": "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM",
                                "key": subkey,
                                "name": name,
                                "value": val,
                                "score": score,
                                "reasons": reasons
                            })
                    except OSError:
                        break
                winreg.CloseKey(k)
            except Exception:
                continue

        for r in results:
            self.log({"type": "persistence", **r})

        return results

    def scan_schtasks(self) -> list[dict]:
        results = []
        try:
            res = subprocess.run(["schtasks", "/Query", "/FO", "LIST", "/V"],
                                 capture_output=True, text=True)
        except Exception:
            return []

        if res.returncode != 0:
            return []

        block = {}
        for line in res.stdout.splitlines():
            if not line.strip():
                if block:
                    results.append(block)
                    block = {}
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                block[k.strip()] = v.strip()
        if block:
            results.append(block)

        suspicious = []
        for item in results:
            name = item.get("TaskName") or item.get("Task Name") or ""
            action = item.get("Task To Run") or item.get("Actions") or item.get("Action") or ""
            if not name and not action:
                continue
            lower = action.lower()
            score = 0
            reasons = []

            if "powershell" in lower and ("-enc" in lower or "encodedcommand" in lower):
                score += 6
                reasons.append("task:powershell_encoded")

            if any(m in lower for m in SUSPICIOUS_DIR_MARKERS):
                score += 3
                reasons.append("task:suspicious_path")

            if any(x in lower for x in ["mshta", "rundll32", "wscript", "cscript"]):
                score += 3
                reasons.append("task:suspicious_host")

            if score >= 4:
                out = {
                    "name": name,
                    "action": action,
                    "score": score,
                    "reasons": reasons,
                }
                suspicious.append(out)
                self.log({"type": "persistence_task", **out})

        return suspicious

    def scan_services(self) -> list[dict]:
        results = []
        try:
            res = subprocess.run(["sc", "query", "state=", "all"], capture_output=True, text=True)
        except Exception:
            return []

        if res.returncode != 0:
            return []

        names = []
        for line in res.stdout.splitlines():
            line = line.strip()
            if line.startswith("SERVICE_NAME:"):
                names.append(line.split(":", 1)[1].strip())

        for name in names:
            try:
                qc = subprocess.run(["sc", "qc", name], capture_output=True, text=True)
            except Exception:
                continue
            if qc.returncode != 0:
                continue
            bin_path = ""
            for line in qc.stdout.splitlines():
                if "BINARY_PATH_NAME" in line:
                    _, val = line.split(":", 1)
                    bin_path = val.strip()
                    break
            lower = bin_path.lower()
            if "windows\\system32" in lower:
                continue
            score = 0
            reasons = []
            if any(ext in lower for ext in [".ps1", ".vbs", ".js", ".bat", ".cmd"]):
                score += 3
                reasons.append("service:script")
            if any(m in lower for m in SUSPICIOUS_DIR_MARKERS):
                score += 3
                reasons.append("service:suspicious_path")
            if any(x in lower for x in ["mshta", "rundll32", "wscript", "cscript", "powershell"]):
                score += 3
                reasons.append("service:suspicious_host")
            if " -enc" in lower or "encodedcommand" in lower:
                score += 6
                reasons.append("service:powershell_encoded")
            signed = is_file_signed_windows(Path(bin_path.strip('"')))
            if signed is False:
                score += 2
                reasons.append("service:signed_missing")

            if score >= 4:
                out = {
                    "name": name,
                    "bin_path": bin_path,
                    "score": score,
                    "reasons": reasons,
                }
                results.append(out)
                self.log({"type": "persistence_service", **out})

        return results

    def build_timeline(self, last_n: int = 500) -> list[dict]:
        if not self.log_path.exists():
            return []
        events = []
        try:
            from collections import deque

            with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
                dq = deque(f, maxlen=last_n)
            for line in dq:
                try:
                    ev = json.loads(line.strip())
                except Exception:
                    continue
                events.append(ev)
        except Exception:
            return []

        for ev in events:
            et = ev.get("type", "event")
            if et == "finding":
                ev["summary"] = f"{ev.get('level')} {ev.get('path')} score={ev.get('score')}"
            elif et == "quarantine":
                ev["summary"] = f"{ev.get('src')} -> {ev.get('dst')}"
            elif et == "network":
                ev["summary"] = f"{ev.get('remote_ip')}:{ev.get('remote_port')} pid={ev.get('pid')} score={ev.get('score')}"
            elif et == "persistence_task":
                ev["summary"] = f"task {ev.get('name')} score={ev.get('score')}"
            elif et == "persistence_service":
                ev["summary"] = f"service {ev.get('name')} score={ev.get('score')}"
            elif et == "persistence":
                ev["summary"] = f"runkey {ev.get('name')} score={ev.get('score')}"
            else:
                ev["summary"] = str(ev)

        def key_fn(ev):
            return ev.get("timestamp", "")

        events.sort(key=key_fn)
        return events
