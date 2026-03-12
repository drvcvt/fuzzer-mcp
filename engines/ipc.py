"""
Named Pipe IPC engine using ctypes for Windows API access.

Provides enumeration, security inspection, connection, and fuzzing
of Windows named pipes.
"""

import ctypes
import ctypes.wintypes as wintypes
import os
import time
from typing import Dict, List, Optional, Tuple

from .mutation import mutate

# Windows API constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000
PIPE_READMODE_MESSAGE = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

ERROR_PIPE_BUSY = 231
ERROR_MORE_DATA = 234
ERROR_NO_DATA = 232
ERROR_PIPE_NOT_CONNECTED = 233
ERROR_BROKEN_PIPE = 109

# Security descriptor constants
OWNER_SECURITY_INFORMATION = 0x00000001
GROUP_SECURITY_INFORMATION = 0x00000002
DACL_SECURITY_INFORMATION = 0x00000004
SACL_SECURITY_INFORMATION = 0x00000008
SE_FILE_OBJECT = 1
SDDL_REVISION_1 = 1

kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32

# Function prototypes
kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE
]

kernel32.WriteFile.restype = wintypes.BOOL
kernel32.WriteFile.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p
]

kernel32.ReadFile.restype = wintypes.BOOL
kernel32.ReadFile.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p
]

kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

kernel32.WaitNamedPipeW.restype = wintypes.BOOL
kernel32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]

kernel32.GetLastError.restype = wintypes.DWORD

kernel32.SetNamedPipeHandleState.restype = wintypes.BOOL
kernel32.SetNamedPipeHandleState.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)
]

# GetSecurityInfo
advapi32.GetSecurityInfo.restype = wintypes.DWORD
advapi32.GetSecurityInfo.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
    ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(ctypes.c_void_p)
]

# ConvertSecurityDescriptorToStringSecurityDescriptorW
advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
    ctypes.POINTER(ctypes.c_wchar_p), ctypes.POINTER(wintypes.ULONG)
]

kernel32.LocalFree.restype = wintypes.HANDLE
kernel32.LocalFree.argtypes = [wintypes.HANDLE]


def enumerate_pipes() -> List[str]:
    """Enumerate all named pipes on the system."""
    pipes = []
    try:
        pipe_dir = r"//./pipe/"
        entries = os.listdir(pipe_dir)
        pipes = sorted(entries)
    except OSError as e:
        raise RuntimeError(f"Failed to enumerate pipes: {e}")
    return pipes


def get_pipe_security_info(pipe_name: str) -> Dict:
    """Get security descriptor (DACL) for a named pipe."""
    if not pipe_name.startswith("\\\\.\\pipe\\"):
        pipe_path = f"\\\\.\\pipe\\{pipe_name}"
    else:
        pipe_path = pipe_name

    handle = kernel32.CreateFileW(
        pipe_path,
        GENERIC_READ,
        0,
        None,
        OPEN_EXISTING,
        0,
        None
    )

    result = {"pipe": pipe_path, "accessible": False, "sddl": None, "error": None}

    if handle == INVALID_HANDLE_VALUE:
        # Try with lower permissions
        handle = kernel32.CreateFileW(
            pipe_path,
            0x00020000,  # READ_CONTROL
            0,
            None,
            OPEN_EXISTING,
            0,
            None
        )

    if handle == INVALID_HANDLE_VALUE:
        err = kernel32.GetLastError()
        result["error"] = f"Cannot open pipe (error {err})"
        return result

    result["accessible"] = True

    try:
        pSD = ctypes.c_void_p()
        pDacl = ctypes.c_void_p()

        ret = advapi32.GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None, None,
            ctypes.byref(pDacl),
            None,
            ctypes.byref(pSD)
        )

        if ret == 0 and pSD.value:
            sddl_str = ctypes.c_wchar_p()
            sddl_len = wintypes.ULONG()
            if advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                pSD,
                SDDL_REVISION_1,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                ctypes.byref(sddl_str),
                ctypes.byref(sddl_len)
            ):
                result["sddl"] = sddl_str.value
                kernel32.LocalFree(sddl_str)
            kernel32.LocalFree(pSD)
        else:
            result["error"] = f"GetSecurityInfo failed (error {ret})"
    finally:
        kernel32.CloseHandle(handle)

    return result


def connect_and_send(pipe_name: str, data: bytes,
                     timeout: int = 5000) -> Dict:
    """Connect to a named pipe, send data, and receive response."""
    if not pipe_name.startswith("\\\\.\\pipe\\"):
        pipe_path = f"\\\\.\\pipe\\{pipe_name}"
    else:
        pipe_path = pipe_name

    result = {
        "pipe": pipe_path,
        "connected": False,
        "sent_bytes": 0,
        "received_bytes": 0,
        "response": None,
        "error": None,
    }

    # Wait for pipe to be available
    if not kernel32.WaitNamedPipeW(pipe_path, timeout):
        err = kernel32.GetLastError()
        if err == ERROR_PIPE_BUSY:
            result["error"] = "Pipe is busy (timeout waiting)"
        else:
            result["error"] = f"WaitNamedPipe failed (error {err})"
        return result

    handle = kernel32.CreateFileW(
        pipe_path,
        GENERIC_READ | GENERIC_WRITE,
        0,
        None,
        OPEN_EXISTING,
        0,
        None
    )

    if handle == INVALID_HANDLE_VALUE:
        err = kernel32.GetLastError()
        result["error"] = f"CreateFile failed (error {err})"
        return result

    result["connected"] = True

    try:
        # Send data
        bytes_written = wintypes.DWORD(0)
        success = kernel32.WriteFile(
            handle,
            data,
            len(data),
            ctypes.byref(bytes_written),
            None
        )
        if success:
            result["sent_bytes"] = bytes_written.value
        else:
            err = kernel32.GetLastError()
            result["error"] = f"WriteFile failed (error {err})"
            return result

        # Read response
        buf_size = 4096
        buf = ctypes.create_string_buffer(buf_size)
        bytes_read = wintypes.DWORD(0)
        success = kernel32.ReadFile(
            handle,
            buf,
            buf_size,
            ctypes.byref(bytes_read),
            None
        )
        if success or kernel32.GetLastError() == ERROR_MORE_DATA:
            result["received_bytes"] = bytes_read.value
            result["response"] = buf.raw[:bytes_read.value].hex()
        else:
            err = kernel32.GetLastError()
            if err == ERROR_BROKEN_PIPE:
                result["error"] = "Pipe closed by server (broken pipe)"
            elif err == ERROR_NO_DATA:
                result["received_bytes"] = 0
                result["response"] = ""
            else:
                result["error"] = f"ReadFile failed (error {err})"

    finally:
        kernel32.CloseHandle(handle)

    return result


def fuzz_pipe(pipe_name: str, seed_data: bytes, iterations: int = 100,
              mutation_strategy: str = "all", timeout: int = 5000,
              rng_seed: Optional[int] = None) -> Dict:
    """Fuzz a named pipe with mutated inputs."""
    mutations = mutate(seed_data, strategy=mutation_strategy,
                       count=iterations, seed=rng_seed)

    results = {
        "pipe": pipe_name,
        "iterations": len(mutations),
        "seed_data_hex": seed_data.hex(),
        "strategy": mutation_strategy,
        "crashes": [],
        "errors": [],
        "interesting": [],
        "stats": {
            "connected": 0,
            "sent": 0,
            "responses": 0,
            "errors": 0,
            "timeouts": 0,
        }
    }

    for i, payload in enumerate(mutations):
        try:
            r = connect_and_send(pipe_name, payload, timeout)
            if r["connected"]:
                results["stats"]["connected"] += 1
            if r["sent_bytes"] > 0:
                results["stats"]["sent"] += 1
            if r["received_bytes"] and r["received_bytes"] > 0:
                results["stats"]["responses"] += 1

            if r["error"]:
                if "busy" in str(r["error"]).lower() or "timeout" in str(r["error"]).lower():
                    results["stats"]["timeouts"] += 1
                else:
                    results["stats"]["errors"] += 1
                    # Log first few unique errors
                    err_entry = {
                        "iteration": i,
                        "payload_hex": payload.hex()[:200],
                        "error": r["error"]
                    }
                    if len(results["errors"]) < 50:
                        results["errors"].append(err_entry)

            # Check for interesting responses (different from baseline)
            if r["response"] and len(r["response"]) > 0:
                entry = {
                    "iteration": i,
                    "payload_hex": payload.hex()[:200],
                    "response_hex": r["response"][:200],
                    "response_len": r["received_bytes"]
                }
                if len(results["interesting"]) < 50:
                    results["interesting"].append(entry)

        except Exception as e:
            crash_entry = {
                "iteration": i,
                "payload_hex": payload.hex()[:200],
                "exception": str(e),
                "exception_type": type(e).__name__
            }
            results["crashes"].append(crash_entry)

        # Small delay to avoid overwhelming the pipe server
        if i % 10 == 0:
            time.sleep(0.01)

    return results
