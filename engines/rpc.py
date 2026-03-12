"""
RPC endpoint enumeration engine.

Uses impacket rpcdump if available, with fallback to registry
and raw RPC endpoint mapper queries.
"""

import socket
import struct
import subprocess
import winreg
from typing import Dict, List, Optional

# Try importing impacket
_HAS_IMPACKET = False
try:
    from impacket.dcerpc.v5 import transport, epm
    from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE
    _HAS_IMPACKET = True
except ImportError:
    pass

# Well-known RPC interface UUIDs
KNOWN_INTERFACES = {
    "e1af8308-5d1f-11c9-91a4-08002b14a0fa": "EPM (Endpoint Mapper)",
    "afa8bd80-7d8a-11c9-bef4-08002b102989": "MGMT (Remote Management)",
    "12345778-1234-abcd-ef00-0123456789ab": "LSA (Local Security Authority)",
    "12345778-1234-abcd-ef00-0123456789ac": "SAMR (Security Account Manager)",
    "338cd001-2244-31f1-aaaa-900038001003": "Winreg (Remote Registry)",
    "367abb81-9844-35f1-ad32-98f038001003": "SCMR (Service Control Manager)",
    "4b324fc8-1670-01d3-1278-5a47bf6ee188": "SRVSVC (Server Service)",
    "12345678-1234-abcd-ef00-01234567cffb": "NETLOGON",
    "3919286a-b10c-11d0-9ba8-00c04fd92ef5": "DSSETUP",
    "e3514235-4b06-11d1-ab04-00c04fc2dcd2": "DRSUAPI",
    "86d35949-83c9-4044-b424-db363231fd0c": "Task Scheduler",
    "1ff70682-0a51-30e8-076d-740be8cee98b": "ATSVC (AT Scheduler)",
    "378e52b0-c0a9-11cf-822d-00aa0051e40f": "Task Scheduler 2.0",
    "6bffd098-a112-3610-9833-46c3f87e345a": "WKSSVC (Workstation Service)",
    "4fc742e0-4a10-11cf-8273-00aa004ae673": "DFSNM (DFS)",
    "c681d488-d850-11d0-8c52-00c04fd90f7e": "EFS (Encrypting File System)",
    "76f03f96-cdfd-44fc-a22c-64950a001209": "IRemoteWinspool",
}

# EPM protocol tower constants
EPM_PROTOCOL_TCP = 0x07
EPM_PROTOCOL_UDP = 0x08
EPM_PROTOCOL_IP = 0x09
EPM_PROTOCOL_PIPE = 0x0F
EPM_PROTOCOL_NETBIOS = 0x11
EPM_PROTOCOL_HTTP = 0x1F


def enumerate_rpc_endpoints(target: str = "127.0.0.1") -> Dict:
    """Enumerate RPC endpoints on a target."""
    result = {
        "target": target,
        "endpoints": [],
        "method": None,
        "error": None,
    }

    # Method 1: impacket
    if _HAS_IMPACKET:
        try:
            result["method"] = "impacket"
            string_binding = f"ncacn_ip_tcp:{target}[135]"
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.setRemoteHost(target)

            dce = rpctransport.get_dce_rpc()
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_NONE)
            dce.connect()
            dce.bind(epm.MSRPC_UUID_PORTMAP)

            resp = epm.hept_lookup(None, dce_rpc=dce)

            for entry in resp:
                try:
                    binding = entry["tower"]["Floors"]
                    uuid_str = str(entry.get("annotation", "")).strip("\x00")

                    # Parse tower floors
                    iface_uuid = ""
                    protocol = ""
                    endpoint = ""

                    for floor in binding:
                        proto_id = floor["ProtocolId"]
                        if proto_id == 0x0D:  # UUID
                            iface_uuid = str(floor.get("InterfaceUUID", ""))
                        elif proto_id == EPM_PROTOCOL_TCP:
                            endpoint = f"TCP/{floor.get('Port', '')}"
                            protocol = "ncacn_ip_tcp"
                        elif proto_id == EPM_PROTOCOL_PIPE:
                            endpoint = f"PIPE/{floor.get('PipeName', '')}"
                            protocol = "ncacn_np"
                        elif proto_id == EPM_PROTOCOL_HTTP:
                            endpoint = f"HTTP/{floor.get('Port', '')}"
                            protocol = "ncacn_http"

                    ep_entry = {
                        "uuid": iface_uuid,
                        "known_name": KNOWN_INTERFACES.get(
                            iface_uuid.lower(), "Unknown"),
                        "annotation": uuid_str,
                        "protocol": protocol,
                        "endpoint": endpoint,
                    }
                    result["endpoints"].append(ep_entry)

                except Exception:
                    continue

            dce.disconnect()
            return result

        except Exception as e:
            result["error"] = f"impacket failed: {e}"

    # Method 2: rpcdump.py subprocess
    try:
        proc = subprocess.run(
            ["python", "-m", "impacket.rpcdump", target],
            capture_output=True, text=True, timeout=30
        )
        if proc.returncode == 0 and proc.stdout:
            result["method"] = "rpcdump_cli"
            for line in proc.stdout.splitlines():
                line = line.strip()
                if "Protocol:" in line or "Provider:" in line or "UUID:" in line:
                    # Parse rpcdump output
                    if "UUID:" in line:
                        parts = line.split("UUID:")
                        if len(parts) > 1:
                            uuid_part = parts[1].strip()
                            uuid_val = uuid_part.split()[0] if uuid_part else ""
                            result["endpoints"].append({
                                "uuid": uuid_val,
                                "known_name": KNOWN_INTERFACES.get(
                                    uuid_val.lower(), "Unknown"),
                                "raw_line": line,
                            })
            if result["endpoints"]:
                return result
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # Method 3: Raw EPM query via socket
    try:
        result["method"] = "raw_epm"
        _raw_epm_query(target, result)
        if result["endpoints"]:
            return result
    except Exception as e:
        if not result["error"]:
            result["error"] = f"Raw EPM query failed: {e}"

    # Method 4: Registry fallback (local only)
    if target in ("127.0.0.1", "localhost", "::1"):
        try:
            result["method"] = "registry"
            _registry_rpc_enum(result)
        except Exception as e:
            if not result["error"]:
                result["error"] = f"Registry enumeration failed: {e}"

    return result


def _raw_epm_query(target: str, result: Dict):
    """Send a raw DCE/RPC endpoint mapper lookup request."""
    # Connect to EPM on port 135
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((target, 135))
        _raw_epm_query_inner(sock, result)
    finally:
        sock.close()


def _raw_epm_query_inner(sock: socket.socket, result: Dict):
    """Inner EPM query logic (socket managed by caller)."""

    # DCE/RPC bind request for EPM interface
    # e1af8308-5d1f-11c9-91a4-08002b14a0fa v3.0
    bind_pdu = bytearray([
        0x05, 0x00,  # version 5.0
        0x0B,        # bind
        0x03,        # flags (first+last frag)
        0x10, 0x00, 0x00, 0x00,  # data representation (little-endian)
        0x48, 0x00,  # frag length (72)
        0x00, 0x00,  # auth length
        0x01, 0x00, 0x00, 0x00,  # call id
        0xB8, 0x10,  # max xmit frag
        0xB8, 0x10,  # max recv frag
        0x00, 0x00, 0x00, 0x00,  # assoc group
        0x01,        # num context items
        0x00, 0x00, 0x00,  # padding
        # Context item 0
        0x00, 0x00,  # context id
        0x01,        # num trans syntaxes
        0x00,        # padding
        # Abstract syntax: EPM UUID
        0x08, 0x83, 0xAF, 0xE1,
        0x1F, 0x5D, 0xC9, 0x11,
        0x91, 0xA4, 0x08, 0x00,
        0x2B, 0x14, 0xA0, 0xFA,
        0x03, 0x00,  # version 3.0
        0x00, 0x00,
        # Transfer syntax: NDR
        0x04, 0x5D, 0x88, 0x8A,
        0xEB, 0x1C, 0xC9, 0x11,
        0x9F, 0xE8, 0x08, 0x00,
        0x2B, 0x10, 0x48, 0x60,
        0x02, 0x00, 0x00, 0x00,  # version 2.0
    ])

    sock.send(bind_pdu)
    resp = sock.recv(4096)

    if len(resp) < 24 or resp[2] != 0x0C:  # bind_ack
        return

    # EPM ept_lookup request (simplified)
    # Just query for all entries
    lookup_req = bytearray([
        0x05, 0x00,  # version
        0x00,        # request
        0x03,        # flags
        0x10, 0x00, 0x00, 0x00,  # data representation
        0x00, 0x00,  # frag length (filled below)
        0x00, 0x00,  # auth length
        0x02, 0x00, 0x00, 0x00,  # call id
        0x00, 0x00, 0x00, 0x00,  # alloc hint
        0x00, 0x00,  # context id
        0x02, 0x00,  # opnum = 2 (ept_lookup)
        # inquiry_type = 0 (RPC_C_EP_ALL_ELTS)
        0x00, 0x00, 0x00, 0x00,
        # object UUID (null)
        0x00, 0x00, 0x00, 0x00,
        # interface_id (null referent)
        0x00, 0x00, 0x00, 0x00,
        # vers_option = 0
        0x00, 0x00, 0x00, 0x00,
        # entry_handle (20 bytes of zero = initial)
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        # max_ents
        0x64, 0x00, 0x00, 0x00,  # 100 entries
    ])

    # Fix frag length
    frag_len = len(lookup_req)
    lookup_req[8] = frag_len & 0xFF
    lookup_req[9] = (frag_len >> 8) & 0xFF

    sock.send(lookup_req)

    try:
        resp = sock.recv(65536)
        if resp and len(resp) > 24:
            result["endpoints"].append({
                "note": f"Received {len(resp)} bytes from EPM (raw parse)",
                "raw_size": len(resp),
            })
    except socket.timeout:
        pass


def _registry_rpc_enum(result: Dict):
    """Enumerate RPC endpoints from local registry."""
    # Check for RPC endpoint registrations
    try:
        rpc_key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Rpc\ClientProtocols"
        )
        i = 0
        while True:
            try:
                name = winreg.EnumValue(rpc_key, i)
                result["endpoints"].append({
                    "protocol": name[0],
                    "dll": name[1],
                    "source": "registry",
                })
                i += 1
            except OSError:
                break
        winreg.CloseKey(rpc_key)
    except (OSError, FileNotFoundError):
        pass

    # Also check named pipe endpoints that look like RPC
    try:
        import os
        pipes = os.listdir("//./pipe/")
        rpc_pipes = [p for p in pipes if "rpc" in p.lower() or
                     "epmapper" in p.lower() or "lsass" in p.lower() or
                     "samr" in p.lower() or "netlogon" in p.lower()]
        for pipe in rpc_pipes:
            result["endpoints"].append({
                "pipe": pipe,
                "protocol": "ncacn_np",
                "endpoint": f"\\pipe\\{pipe}",
                "source": "pipe_enum",
            })
    except OSError:
        pass
