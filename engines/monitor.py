"""
Crash monitoring engine.

Monitors Windows Event Log and WER crash dumps for crash events.
Uses win32evtlog if available, falls back to wevtutil.exe subprocess.
"""

import datetime
import os
import subprocess
import time
from typing import Dict, List, Optional

# Try win32 event log API
_HAS_WIN32EVTLOG = False
try:
    import win32evtlog
    import win32con
    _HAS_WIN32EVTLOG = True
except ImportError:
    pass

# Global monitoring state
_monitor_state = {
    "active": False,
    "start_time": None,
    "process_name": None,
    "initial_wer_dumps": set(),
    "crashes_found": [],
}

# WER dump paths
WER_PATHS = [
    os.path.expandvars(r"%LOCALAPPDATA%\CrashDumps"),
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\WER\ReportArchive"),
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\WER\ReportQueue"),
    r"C:\ProgramData\Microsoft\Windows\WER\ReportArchive",
    r"C:\ProgramData\Microsoft\Windows\WER\ReportQueue",
]


def _list_wer_dumps() -> set:
    """List all existing WER crash dump files."""
    dumps = set()
    for wer_path in WER_PATHS:
        if os.path.isdir(wer_path):
            try:
                for entry in os.listdir(wer_path):
                    full_path = os.path.join(wer_path, entry)
                    dumps.add(full_path)
            except OSError:
                pass
    return dumps


def _query_event_log_wevtutil(start_time: datetime.datetime,
                               process_name: Optional[str] = None) -> List[Dict]:
    """Query Windows Event Log using wevtutil.exe."""
    events = []

    # Format time for XPath query
    time_str = start_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # Query Application log for WER events (Event IDs: 1000, 1001, 1002)
    queries = [
        (
            "Application",
            f"*[System[(EventID=1000 or EventID=1001 or EventID=1002) "
            f"and TimeCreated[@SystemTime>='{time_str}']]]"
        ),
        (
            "System",
            f"*[System[(EventID=1001 or EventID=6008 or EventID=41) "
            f"and TimeCreated[@SystemTime>='{time_str}']]]"
        ),
    ]

    for log_name, query in queries:
        try:
            proc = subprocess.run(
                ["wevtutil", "qe", log_name, "/q:" + query,
                 "/f:text", "/c:50"],
                capture_output=True, text=True, timeout=15
            )
            if proc.returncode == 0 and proc.stdout:
                current_event = {}
                for line in proc.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("Event["):
                        if current_event:
                            # Filter by process name if specified
                            if process_name:
                                event_text = str(current_event).lower()
                                if process_name.lower() in event_text:
                                    events.append(current_event)
                            else:
                                events.append(current_event)
                        current_event = {"log": log_name}
                    elif ":" in line:
                        key, _, val = line.partition(":")
                        current_event[key.strip()] = val.strip()

                if current_event:
                    if process_name:
                        event_text = str(current_event).lower()
                        if process_name.lower() in event_text:
                            events.append(current_event)
                    else:
                        events.append(current_event)

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    return events


def _query_event_log_win32(start_time: datetime.datetime,
                            process_name: Optional[str] = None) -> List[Dict]:
    """Query Windows Event Log using pywin32."""
    events = []

    for log_name in ("Application", "System"):
        try:
            handle = win32evtlog.OpenEventLog(None, log_name)
            flags = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                     win32evtlog.EVENTLOG_SEQUENTIAL_READ)

            while True:
                records = win32evtlog.ReadEventLog(handle, flags, 0)
                if not records:
                    break

                for record in records:
                    # Check time
                    event_time = record.TimeGenerated
                    if hasattr(event_time, 'timestamp'):
                        if event_time < start_time:
                            continue

                    # Check event IDs (WER: 1000, 1001, 1002)
                    if record.EventID & 0xFFFF in (1000, 1001, 1002, 6008, 41):
                        event_data = {
                            "log": log_name,
                            "event_id": record.EventID & 0xFFFF,
                            "source": record.SourceName,
                            "time": str(record.TimeGenerated),
                            "category": record.EventCategory,
                        }

                        # Get string inserts
                        if record.StringInserts:
                            event_data["strings"] = list(record.StringInserts)

                        # Filter by process name
                        if process_name:
                            all_text = str(event_data).lower()
                            if process_name.lower() not in all_text:
                                continue

                        events.append(event_data)

            win32evtlog.CloseEventLog(handle)
        except Exception:
            pass

    return events


def start_monitoring(process_name: Optional[str] = None) -> Dict:
    """Start monitoring for crashes."""
    global _monitor_state

    _monitor_state = {
        "active": True,
        "start_time": datetime.datetime.now(),
        "process_name": process_name,
        "initial_wer_dumps": _list_wer_dumps(),
        "crashes_found": [],
    }

    return {
        "status": "monitoring",
        "start_time": _monitor_state["start_time"].isoformat(),
        "process_name": process_name or "(all processes)",
        "initial_wer_dumps": len(_monitor_state["initial_wer_dumps"]),
        "method": "win32evtlog" if _HAS_WIN32EVTLOG else "wevtutil",
    }


def check_crashes() -> Dict:
    """Check for new crashes since monitoring started."""
    global _monitor_state

    if not _monitor_state["active"]:
        return {"error": "Monitoring not active. Call fuzz_monitor_start() first."}

    result = {
        "status": "checking",
        "monitoring_since": _monitor_state["start_time"].isoformat(),
        "process_name": _monitor_state["process_name"] or "(all)",
        "new_wer_dumps": [],
        "event_log_crashes": [],
        "total_new_crashes": 0,
    }

    # Check for new WER dumps
    current_dumps = _list_wer_dumps()
    new_dumps = current_dumps - _monitor_state["initial_wer_dumps"]
    for dump_path in new_dumps:
        dump_info = {"path": dump_path}
        try:
            stat = os.stat(dump_path)
            dump_info["size"] = stat.st_size
            dump_info["created"] = datetime.datetime.fromtimestamp(
                stat.st_ctime).isoformat()
        except OSError:
            pass

        # Try to read WER report.ini if it's a directory
        if os.path.isdir(dump_path):
            report_file = os.path.join(dump_path, "Report.wer")
            if os.path.isfile(report_file):
                try:
                    with open(report_file, "r", encoding="utf-16-le",
                              errors="replace") as f:
                        content = f.read(4096)
                    dump_info["report_content"] = content[:2048]
                except OSError:
                    pass

        result["new_wer_dumps"].append(dump_info)

    # Check event log
    if _HAS_WIN32EVTLOG:
        events = _query_event_log_win32(
            _monitor_state["start_time"],
            _monitor_state["process_name"]
        )
    else:
        events = _query_event_log_wevtutil(
            _monitor_state["start_time"],
            _monitor_state["process_name"]
        )

    result["event_log_crashes"] = events
    result["total_new_crashes"] = len(new_dumps) + len(events)

    # Update state
    _monitor_state["crashes_found"].extend(
        [{"type": "wer", "path": d["path"]} for d in result["new_wer_dumps"]]
    )
    _monitor_state["crashes_found"].extend(
        [{"type": "event", "data": e} for e in events]
    )

    return result


def stop_monitoring() -> Dict:
    """Stop monitoring and return summary."""
    global _monitor_state

    if not _monitor_state["active"]:
        return {"error": "Monitoring not active."}

    # Do one final check
    final_check = check_crashes()

    elapsed = (datetime.datetime.now() -
               _monitor_state["start_time"]).total_seconds()

    summary = {
        "status": "stopped",
        "duration_seconds": elapsed,
        "process_name": _monitor_state["process_name"] or "(all)",
        "total_crashes_found": final_check["total_new_crashes"],
        "crashes": final_check.get("new_wer_dumps", []) + final_check.get("event_log_crashes", []),
        "final_check": final_check,
    }

    _monitor_state["active"] = False
    return summary
