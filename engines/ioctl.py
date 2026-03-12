"""
IOCTL engine using ctypes for Windows API access.

Provides device enumeration, IOCTL sending, security inspection,
and IOCTL fuzzing/bruteforcing.
"""

import ctypes
import ctypes.wintypes as wintypes
import struct
import time
import winreg
from typing import Dict, List, Optional, Tuple

from .mutation import mutate

# Windows API constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# IOCTL error codes
ERROR_INVALID_FUNCTION = 1
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_HANDLE = 6
ERROR_INVALID_PARAMETER = 87
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_NOACCESS = 998

# Security
SE_FILE_OBJECT = 1
OWNER_SECURITY_INFORMATION = 0x00000001
DACL_SECURITY_INFORMATION = 0x00000004
SDDL_REVISION_1 = 1

kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32
ntdll = ctypes.windll.ntdll

# DeviceIoControl
kernel32.DeviceIoControl.restype = wintypes.BOOL
kernel32.DeviceIoControl.argtypes = [
    wintypes.HANDLE,   # hDevice
    wintypes.DWORD,    # dwIoControlCode
    ctypes.c_void_p,   # lpInBuffer
    wintypes.DWORD,    # nInBufferSize
    ctypes.c_void_p,   # lpOutBuffer
    wintypes.DWORD,    # nOutBufferSize
    ctypes.POINTER(wintypes.DWORD),  # lpBytesReturned
    ctypes.c_void_p    # lpOverlapped
]

kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE
]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.GetLastError.restype = wintypes.DWORD

# QueryDosDeviceW
kernel32.QueryDosDeviceW.restype = wintypes.DWORD
kernel32.QueryDosDeviceW.argtypes = [
    wintypes.LPCWSTR, ctypes.c_wchar_p, wintypes.DWORD
]

# Security
advapi32.GetSecurityInfo.restype = wintypes.DWORD
advapi32.GetSecurityInfo.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
    ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(ctypes.c_void_p)
]
advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
    ctypes.POINTER(ctypes.c_wchar_p), ctypes.POINTER(wintypes.ULONG)
]
kernel32.LocalFree.restype = wintypes.HANDLE
kernel32.LocalFree.argtypes = [wintypes.HANDLE]


def _parse_ioctl_code(code) -> int:
    """Parse an IOCTL code from int or hex string."""
    if isinstance(code, int):
        return code
    if isinstance(code, str):
        code = code.strip()
        if code.startswith("0x") or code.startswith("0X"):
            return int(code, 16)
        try:
            return int(code)
        except ValueError:
            return int(code, 16)
    raise ValueError(f"Invalid IOCTL code: {code}")


def _ioctl_components(code: int) -> Dict:
    """Decode IOCTL code into components (device type, function, method, access)."""
    device_type = (code >> 16) & 0xFFFF
    access = (code >> 14) & 0x3
    function = (code >> 2) & 0xFFF
    method = code & 0x3

    access_map = {0: "FILE_ANY_ACCESS", 1: "FILE_READ_ACCESS",
                  2: "FILE_WRITE_ACCESS", 3: "FILE_READ_WRITE_ACCESS"}
    method_map = {0: "METHOD_BUFFERED", 1: "METHOD_IN_DIRECT",
                  2: "METHOD_OUT_DIRECT", 3: "METHOD_NEITHER"}

    return {
        "code": f"0x{code:08X}",
        "device_type": f"0x{device_type:04X}",
        "function": f"0x{function:03X}",
        "access": access_map.get(access, f"0x{access:X}"),
        "method": method_map.get(method, f"0x{method:X}"),
    }


def enumerate_devices() -> List[Dict]:
    """Enumerate device objects and symbolic links."""
    devices = []

    # Method 1: QueryDosDevice to list all dos devices
    buf_size = 65536
    buf = ctypes.create_unicode_buffer(buf_size)
    ret = kernel32.QueryDosDeviceW(None, buf, buf_size)

    if ret > 0:
        # Parse null-separated list from unicode buffer
        # buf.value only returns up to first null, so use indexing
        full_str = ctypes.wstring_at(buf, ret)
        names = []
        current = ""
        for ch in full_str:
            if ch == '\x00':
                if current:
                    names.append(current)
                    current = ""
            else:
                current += ch

        for name in names:
            # Get target for each device
            target_buf = ctypes.create_unicode_buffer(1024)
            tret = kernel32.QueryDosDeviceW(name, target_buf, 1024)
            target = ""
            if tret > 0:
                target = target_buf.value

            entry = {
                "name": name,
                "path": f"\\\\.\\{name}",
                "target": target,
                "type": "unknown",
            }

            # Classify device type
            target_lower = target.lower()
            if "\\device\\" in target_lower:
                entry["type"] = "device"
            elif "\\dosdevices\\" in target_lower:
                entry["type"] = "dosdevice"
            elif name.endswith(":"):
                entry["type"] = "drive"

            devices.append(entry)

    # Method 2: Check registry for driver services
    device_names = {d["name"] for d in devices}
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Services")
        i = 0
        while True:
            try:
                svc_name = winreg.EnumKey(key, i)
                try:
                    svc_key = winreg.OpenKey(key, svc_name)
                    try:
                        svc_type = winreg.QueryValueEx(svc_key, "Type")[0]
                        # Type 1 = kernel driver, Type 2 = file system driver
                        if svc_type in (1, 2):
                            # Check if already in list
                            if svc_name not in device_names:
                                devices.append({
                                    "name": svc_name,
                                    "path": f"\\\\.\\{svc_name}",
                                    "target": f"(driver service, type={svc_type})",
                                    "type": "driver",
                                })
                                device_names.add(svc_name)
                    except (OSError, FileNotFoundError):
                        pass
                    finally:
                        winreg.CloseKey(svc_key)
                except (OSError, FileNotFoundError):
                    pass
                i += 1
            except OSError:
                break
        winreg.CloseKey(key)
    except (OSError, FileNotFoundError):
        pass

    return devices


def get_device_dacl(device_path: str) -> Dict:
    """Check security descriptor/DACL of a device object."""
    if not device_path.startswith("\\\\.\\"):
        device_path = f"\\\\.\\{device_path}"

    result = {"device": device_path, "accessible": False, "sddl": None, "error": None}

    # Try opening with READ_CONTROL only
    handle = kernel32.CreateFileW(
        device_path,
        0x00020000,  # READ_CONTROL
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        0,
        None
    )

    if handle == INVALID_HANDLE_VALUE:
        err = kernel32.GetLastError()
        result["error"] = f"Cannot open device (error {err})"

        # Try with even lower permissions
        handle = kernel32.CreateFileW(
            device_path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
            None, OPEN_EXISTING, 0, None
        )
        if handle == INVALID_HANDLE_VALUE:
            return result

    result["accessible"] = True
    result["error"] = None  # Clear error from first failed attempt

    try:
        pSD = ctypes.c_void_p()
        ret = advapi32.GetSecurityInfo(
            handle, SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None, None, None, None, ctypes.byref(pSD)
        )

        if ret == 0 and pSD.value:
            sddl_str = ctypes.c_wchar_p()
            sddl_len = wintypes.ULONG()
            if advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                pSD, SDDL_REVISION_1,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                ctypes.byref(sddl_str), ctypes.byref(sddl_len)
            ):
                result["sddl"] = sddl_str.value
                kernel32.LocalFree(sddl_str)
            kernel32.LocalFree(pSD)
        else:
            result["error"] = f"GetSecurityInfo failed (error {ret})"
    finally:
        kernel32.CloseHandle(handle)

    return result


def send_ioctl(device_path: str, ioctl_code, input_buffer: bytes,
               output_size: int = 4096, timeout: int = 5000) -> Dict:
    """Send a single IOCTL to a device driver."""
    if not device_path.startswith("\\\\.\\"):
        device_path = f"\\\\.\\{device_path}"

    code = _parse_ioctl_code(ioctl_code)
    components = _ioctl_components(code)

    result = {
        "device": device_path,
        "ioctl_code": f"0x{code:08X}",
        "ioctl_components": components,
        "input_size": len(input_buffer),
        "output_size": 0,
        "output_hex": None,
        "success": False,
        "error": None,
        "win32_error": None,
    }

    handle = kernel32.CreateFileW(
        device_path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        0,
        None
    )

    if handle == INVALID_HANDLE_VALUE:
        # Try read-only
        handle = kernel32.CreateFileW(
            device_path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None
        )

    if handle == INVALID_HANDLE_VALUE:
        err = kernel32.GetLastError()
        result["error"] = f"Cannot open device (error {err})"
        result["win32_error"] = err
        return result

    try:
        out_buf = ctypes.create_string_buffer(output_size)
        bytes_returned = wintypes.DWORD(0)

        in_buf = None
        in_size = 0
        if input_buffer:
            in_buf = ctypes.c_char_p(input_buffer)
            in_size = len(input_buffer)

        success = kernel32.DeviceIoControl(
            handle, code,
            in_buf, in_size,
            out_buf, output_size,
            ctypes.byref(bytes_returned),
            None
        )

        if success:
            result["success"] = True
            result["output_size"] = bytes_returned.value
            if bytes_returned.value > 0:
                result["output_hex"] = out_buf.raw[:bytes_returned.value].hex()
        else:
            err = kernel32.GetLastError()
            result["win32_error"] = err
            result["error"] = f"DeviceIoControl failed (error {err})"

            # Still capture any partial output
            if bytes_returned.value > 0:
                result["output_size"] = bytes_returned.value
                result["output_hex"] = out_buf.raw[:bytes_returned.value].hex()

    finally:
        kernel32.CloseHandle(handle)

    return result


def fuzz_ioctl(device_path: str, ioctl_code, seed_buffer: bytes,
               iterations: int = 100, mutation_strategy: str = "all",
               timeout: int = 5000, rng_seed: Optional[int] = None) -> Dict:
    """Fuzz IOCTLs with mutated buffers."""
    code = _parse_ioctl_code(ioctl_code)
    mutations = mutate(seed_buffer, strategy=mutation_strategy,
                       count=iterations, seed=rng_seed)

    results = {
        "device": device_path,
        "ioctl_code": f"0x{code:08X}",
        "iterations": len(mutations),
        "seed_hex": seed_buffer.hex(),
        "strategy": mutation_strategy,
        "crashes": [],
        "interesting": [],
        "errors": [],
        "stats": {
            "success": 0,
            "invalid_function": 0,
            "access_denied": 0,
            "invalid_parameter": 0,
            "other_errors": 0,
        }
    }

    for i, payload in enumerate(mutations):
        try:
            r = send_ioctl(device_path, code, payload, timeout=timeout)

            if r["success"]:
                results["stats"]["success"] += 1
                # Log successful IOCTLs with output as interesting
                if r["output_size"] and r["output_size"] > 0:
                    entry = {
                        "iteration": i,
                        "payload_hex": payload.hex()[:200],
                        "output_hex": (r["output_hex"] or "")[:200],
                        "output_size": r["output_size"],
                    }
                    if len(results["interesting"]) < 50:
                        results["interesting"].append(entry)
            elif r["win32_error"] == ERROR_INVALID_FUNCTION:
                results["stats"]["invalid_function"] += 1
            elif r["win32_error"] == ERROR_ACCESS_DENIED:
                results["stats"]["access_denied"] += 1
            elif r["win32_error"] == ERROR_INVALID_PARAMETER:
                results["stats"]["invalid_parameter"] += 1
            else:
                results["stats"]["other_errors"] += 1
                if len(results["errors"]) < 50:
                    results["errors"].append({
                        "iteration": i,
                        "payload_hex": payload.hex()[:200],
                        "error": r["error"],
                        "win32_error": r["win32_error"],
                    })

        except Exception as e:
            results["crashes"].append({
                "iteration": i,
                "payload_hex": payload.hex()[:200],
                "exception": str(e),
                "exception_type": type(e).__name__,
            })

        if i % 10 == 0:
            time.sleep(0.01)

    return results


def bruteforce_ioctls(device_path: str, range_start: int, range_end: int,
                      timeout: int = 5000) -> Dict:
    """Bruteforce valid IOCTL codes by sending empty buffers."""
    if not device_path.startswith("\\\\.\\"):
        device_path = f"\\\\.\\{device_path}"

    results = {
        "device": device_path,
        "range": f"0x{range_start:08X} - 0x{range_end:08X}",
        "total_codes": 0,
        "valid_codes": [],
        "access_denied_codes": [],
        "error": None,
    }

    # Open handle once for all IOCTLs
    handle = kernel32.CreateFileW(
        device_path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        0,
        None
    )

    if handle == INVALID_HANDLE_VALUE:
        handle = kernel32.CreateFileW(
            device_path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None
        )

    if handle == INVALID_HANDLE_VALUE:
        err = kernel32.GetLastError()
        results["error"] = f"Cannot open device (error {err})"
        return results

    try:
        out_buf = ctypes.create_string_buffer(4096)
        bytes_returned = wintypes.DWORD(0)

        # Iterate through IOCTL codes (step by 4, as method field is 2 bits)
        code = range_start
        while code <= range_end:
            results["total_codes"] += 1

            success = kernel32.DeviceIoControl(
                handle, code,
                None, 0,
                out_buf, 4096,
                ctypes.byref(bytes_returned),
                None
            )

            if success:
                components = _ioctl_components(code)
                results["valid_codes"].append({
                    "code": f"0x{code:08X}",
                    "components": components,
                    "output_size": bytes_returned.value,
                })
            else:
                err = kernel32.GetLastError()
                if err == ERROR_ACCESS_DENIED:
                    results["access_denied_codes"].append({
                        "code": f"0x{code:08X}",
                        "components": _ioctl_components(code),
                    })
                # ERROR_INVALID_FUNCTION means the code is not handled - skip
                # Other errors might be interesting
                elif err not in (ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER,
                                 ERROR_NOACCESS):
                    if len(results["valid_codes"]) + len(results["access_denied_codes"]) < 200:
                        results["valid_codes"].append({
                            "code": f"0x{code:08X}",
                            "components": _ioctl_components(code),
                            "error": err,
                            "note": "Non-standard error (may be valid)",
                        })

            code += 1  # Step by 1: test all method types (BUFFERED/IN_DIRECT/OUT_DIRECT/NEITHER)

            if results["total_codes"] % 100 == 0:
                time.sleep(0.01)

    finally:
        kernel32.CloseHandle(handle)

    return results
