"""
COM object enumeration and interaction engine.

Provides CLSID enumeration, TypeLib inspection, and method invocation.
Uses comtypes/win32com if available, falls back to registry-only.
"""

import winreg
from typing import Dict, List, Optional

# Try importing COM libraries
_HAS_COMTYPES = False
_HAS_WIN32COM = False

try:
    import comtypes
    import comtypes.client
    _HAS_COMTYPES = True
except ImportError:
    pass

try:
    import win32com.client
    import pythoncom
    _HAS_WIN32COM = True
except ImportError:
    pass


def _read_reg_value(key, name: str, default=None):
    """Safely read a registry value."""
    try:
        return winreg.QueryValueEx(key, name)[0]
    except (OSError, FileNotFoundError):
        return default


def _read_reg_default(key, default=""):
    """Read default value of a registry key."""
    try:
        return winreg.QueryValueEx(key, "")[0]
    except (OSError, FileNotFoundError):
        return default


def enumerate_com_classes(filter_str: Optional[str] = None,
                          max_results: int = 500) -> List[Dict]:
    """Enumerate COM classes from CLSID registry."""
    classes = []
    try:
        clsid_key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, "CLSID")
    except (OSError, FileNotFoundError):
        return classes

    i = 0
    while len(classes) < max_results:
        try:
            clsid = winreg.EnumKey(clsid_key, i)
            i += 1

            try:
                sub_key = winreg.OpenKey(clsid_key, clsid)
                name = _read_reg_default(sub_key, "")

                # Apply filter
                if filter_str:
                    filter_lower = filter_str.lower()
                    if (filter_lower not in clsid.lower() and
                            filter_lower not in name.lower()):
                        winreg.CloseKey(sub_key)
                        continue

                entry = {
                    "clsid": clsid,
                    "name": name,
                    "inproc_server": None,
                    "local_server": None,
                    "progid": None,
                    "typelib": None,
                    "threading_model": None,
                }

                # InprocServer32
                try:
                    ips_key = winreg.OpenKey(sub_key, "InprocServer32")
                    entry["inproc_server"] = _read_reg_default(ips_key, "")
                    entry["threading_model"] = _read_reg_value(
                        ips_key, "ThreadingModel", "")
                    winreg.CloseKey(ips_key)
                except (OSError, FileNotFoundError):
                    pass

                # LocalServer32
                try:
                    ls_key = winreg.OpenKey(sub_key, "LocalServer32")
                    entry["local_server"] = _read_reg_default(ls_key, "")
                    winreg.CloseKey(ls_key)
                except (OSError, FileNotFoundError):
                    pass

                # ProgID
                try:
                    pid_key = winreg.OpenKey(sub_key, "ProgID")
                    entry["progid"] = _read_reg_default(pid_key, "")
                    winreg.CloseKey(pid_key)
                except (OSError, FileNotFoundError):
                    pass

                # TypeLib
                try:
                    tl_key = winreg.OpenKey(sub_key, "TypeLib")
                    entry["typelib"] = _read_reg_default(tl_key, "")
                    winreg.CloseKey(tl_key)
                except (OSError, FileNotFoundError):
                    pass

                winreg.CloseKey(sub_key)
                classes.append(entry)

            except (OSError, FileNotFoundError):
                pass

        except OSError:
            break

    winreg.CloseKey(clsid_key)
    return classes


def inspect_com_object(clsid_or_progid: str) -> Dict:
    """Get TypeLib info, interfaces, and methods for a COM object."""
    result = {
        "identifier": clsid_or_progid,
        "clsid": None,
        "progid": None,
        "name": None,
        "interfaces": [],
        "methods": [],
        "properties": [],
        "typelib_info": None,
        "server_info": None,
        "error": None,
    }

    # Resolve CLSID vs ProgID
    clsid = clsid_or_progid
    if not clsid.startswith("{"):
        # It's a ProgID, resolve to CLSID
        try:
            pid_key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, clsid_or_progid)
            try:
                clsid_sub = winreg.OpenKey(pid_key, "CLSID")
                clsid = _read_reg_default(clsid_sub, "")
                winreg.CloseKey(clsid_sub)
            except (OSError, FileNotFoundError):
                pass
            winreg.CloseKey(pid_key)
        except (OSError, FileNotFoundError):
            result["error"] = f"ProgID '{clsid_or_progid}' not found in registry"
            return result
        result["progid"] = clsid_or_progid

    result["clsid"] = clsid

    # Read registry info
    try:
        clsid_key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, f"CLSID\\{clsid}")
        result["name"] = _read_reg_default(clsid_key, "")

        # Server info
        server_info = {}
        try:
            ips_key = winreg.OpenKey(clsid_key, "InprocServer32")
            server_info["inproc_server"] = _read_reg_default(ips_key, "")
            server_info["threading_model"] = _read_reg_value(
                ips_key, "ThreadingModel", "")
            winreg.CloseKey(ips_key)
        except (OSError, FileNotFoundError):
            pass

        try:
            ls_key = winreg.OpenKey(clsid_key, "LocalServer32")
            server_info["local_server"] = _read_reg_default(ls_key, "")
            winreg.CloseKey(ls_key)
        except (OSError, FileNotFoundError):
            pass

        result["server_info"] = server_info

        # TypeLib
        try:
            tl_key = winreg.OpenKey(clsid_key, "TypeLib")
            typelib_id = _read_reg_default(tl_key, "")
            result["typelib_info"] = {"typelib_id": typelib_id}
            winreg.CloseKey(tl_key)
        except (OSError, FileNotFoundError):
            pass

        winreg.CloseKey(clsid_key)
    except (OSError, FileNotFoundError):
        result["error"] = f"CLSID '{clsid}' not found in registry"
        return result

    # Try to get type information via COM
    if _HAS_COMTYPES:
        try:
            obj = comtypes.CoCreateInstance(clsid)
            # Try to get IDispatch info
            try:
                import comtypes.automation
                disp = obj.QueryInterface(comtypes.automation.IDispatch)
                ti = disp.GetTypeInfo(0, 0)
                if ti:
                    ta = ti.GetTypeAttr()
                    result["interfaces"].append({
                        "name": "IDispatch",
                        "num_methods": ta.cFuncs,
                        "num_properties": ta.cVars,
                    })
                    for fi in range(ta.cFuncs):
                        fd = ti.GetFuncDesc(fi)
                        names = ti.GetNames(fd.memid, 10)
                        if names:
                            result["methods"].append({
                                "name": names[0],
                                "memid": fd.memid,
                                "params": len(names) - 1,
                                "invoke_kind": fd.invkind,
                            })
                    for vi in range(ta.cVars):
                        vd = ti.GetVarDesc(vi)
                        names = ti.GetNames(vd.memid, 1)
                        if names:
                            result["properties"].append({
                                "name": names[0],
                                "memid": vd.memid,
                            })
            except Exception:
                pass
        except Exception as e:
            result["error"] = f"COM instantiation failed: {e}"

    elif _HAS_WIN32COM:
        try:
            identifier = clsid_or_progid if result["progid"] else clsid
            obj = win32com.client.Dispatch(identifier)
            # Try to enumerate methods/properties
            try:
                ti = obj._oleobj_.GetTypeInfo()
                ta = ti.GetTypeAttr()
                for fi in range(ta.cFuncs):
                    fd = ti.GetFuncDesc(fi)
                    names = ti.GetNames(fd.memid, 10)
                    if names:
                        result["methods"].append({
                            "name": names[0],
                            "memid": fd.memid,
                            "params": len(names) - 1,
                        })
            except Exception:
                pass
        except Exception as e:
            if not result["error"]:
                result["error"] = f"COM instantiation failed: {e}"
    else:
        if not result["error"]:
            result["error"] = ("No COM library available (install comtypes or pywin32). "
                               "Showing registry info only.")

    return result


def invoke_com_method(clsid_or_progid: str, method_name: str,
                      args: Optional[List] = None) -> Dict:
    """Invoke a method on a COM object."""
    result = {
        "identifier": clsid_or_progid,
        "method": method_name,
        "args": args,
        "return_value": None,
        "error": None,
    }

    if not _HAS_WIN32COM and not _HAS_COMTYPES:
        result["error"] = "No COM library available (install comtypes or pywin32)"
        return result

    args = args or []

    if _HAS_WIN32COM:
        try:
            obj = win32com.client.Dispatch(clsid_or_progid)
            method = getattr(obj, method_name, None)
            if method is None:
                result["error"] = f"Method '{method_name}' not found on COM object"
                return result
            ret = method(*args)
            result["return_value"] = str(ret) if ret is not None else None
        except Exception as e:
            result["error"] = f"Invocation failed: {type(e).__name__}: {e}"
    elif _HAS_COMTYPES:
        try:
            obj = comtypes.CoCreateInstance(clsid_or_progid)
            method = getattr(obj, method_name, None)
            if method is None:
                result["error"] = f"Method '{method_name}' not found on COM object"
                return result
            ret = method(*args)
            result["return_value"] = str(ret) if ret is not None else None
        except Exception as e:
            result["error"] = f"Invocation failed: {type(e).__name__}: {e}"

    return result
