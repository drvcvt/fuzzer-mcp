"""
Fuzzer/IPC MCP Server for Windows Bug Bounty Research.

A FastMCP server providing tools for fuzzing Windows IPC mechanisms:
Named Pipes, IOCTLs, COM objects, and RPC endpoints.

Includes mutation engine, crash monitoring, and PoC generation.
"""

import json
import os
import sys
from typing import Optional

from fastmcp import FastMCP

# Add parent dir to path for engine imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engines import mutation as mutation_engine
from engines import ipc as ipc_engine
from engines import ioctl as ioctl_engine
from engines import com as com_engine
from engines import rpc as rpc_engine
from engines import monitor as monitor_engine

mcp = FastMCP("Fuzzer MCP")

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")


# ============================================================
# Helper functions
# ============================================================

def _hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes, handling various formats."""
    if not hex_str:
        return b""
    hex_str = hex_str.strip()
    if hex_str.startswith("0x") or hex_str.startswith("0X"):
        hex_str = hex_str[2:]
    hex_str = hex_str.replace(" ", "").replace("-", "")
    return bytes.fromhex(hex_str)


def _parse_int(value, default: int = 0) -> int:
    """Parse an integer from string or int, supporting hex."""
    if value is None:
        return default
    if isinstance(value, int):
        return value
    value = str(value).strip()
    if value.startswith("0x") or value.startswith("0X"):
        return int(value, 16)
    return int(value)


def _fmt_header(title: str) -> str:
    return f"## {title}\n"


def _fmt_table(headers: list, rows: list) -> str:
    """Format data as a markdown table."""
    if not rows:
        return "_No data_\n"
    lines = ["| " + " | ".join(str(h) for h in headers) + " |"]
    lines.append("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(lines) + "\n"


def _fmt_dict(d: dict, indent: int = 0) -> str:
    """Format a dict as markdown key-value pairs."""
    prefix = "  " * indent
    lines = []
    for k, v in d.items():
        if isinstance(v, dict):
            lines.append(f"{prefix}- **{k}**:")
            lines.append(_fmt_dict(v, indent + 1))
        elif isinstance(v, list) and len(v) > 0 and isinstance(v[0], dict):
            lines.append(f"{prefix}- **{k}**: ({len(v)} items)")
            for i, item in enumerate(v[:20]):
                lines.append(f"{prefix}  - Item {i}:")
                lines.append(_fmt_dict(item, indent + 2))
            if len(v) > 20:
                lines.append(f"{prefix}  - _... and {len(v) - 20} more_")
        elif isinstance(v, list):
            lines.append(f"{prefix}- **{k}**: {', '.join(str(x) for x in v[:50])}")
            if len(v) > 50:
                lines.append(f"{prefix}  _... and {len(v) - 50} more_")
        else:
            lines.append(f"{prefix}- **{k}**: `{v}`")
    return "\n".join(lines)


# ============================================================
# Named Pipe Tools
# ============================================================

@mcp.tool()
async def fuzz_pipe_enum() -> str:
    """Enumerate named pipes on the system (list \\\\.\\pipe\\*)."""
    try:
        pipes = ipc_engine.enumerate_pipes()
    except Exception as e:
        return f"## Error\n\nFailed to enumerate pipes: {e}\n"

    output = _fmt_header("Named Pipes Enumeration")
    output += f"**Total pipes found**: {len(pipes)}\n\n"

    if pipes:
        # Group by prefix for readability
        groups = {}
        for p in pipes:
            prefix = p.split("\\")[0] if "\\" in p else p.split("/")[0] if "/" in p else p
            # Use first meaningful segment
            parts = p.replace("\\", "/").split("/")
            group_key = parts[0] if parts else "other"
            groups.setdefault(group_key, []).append(p)

        # Show all pipes in a table
        rows = [(i + 1, p, f"`\\\\.\\pipe\\{p}`") for i, p in enumerate(pipes)]
        output += _fmt_table(["#", "Name", "Full Path"], rows[:200])
        if len(pipes) > 200:
            output += f"\n_... and {len(pipes) - 200} more pipes_\n"

    return output


@mcp.tool()
async def fuzz_pipe_info(pipe_name: str) -> str:
    """Get security descriptor/DACL info for a named pipe.

    Args:
        pipe_name: Name of the pipe (e.g. 'MyPipe' or '\\\\.\\pipe\\MyPipe')
    """
    try:
        info = ipc_engine.get_pipe_security_info(pipe_name)
    except Exception as e:
        return f"## Error\n\nFailed to get pipe info: {e}\n"

    output = _fmt_header(f"Pipe Info: {pipe_name}")
    output += _fmt_dict(info) + "\n"

    if info.get("sddl"):
        output += "\n### SDDL Breakdown\n"
        output += f"```\n{info['sddl']}\n```\n"
        output += "\n_Parse SDDL: O=Owner, G=Group, D=DACL, S=SACL_\n"
        output += "_ACE format: (type;flags;rights;object_guid;inherit_guid;sid)_\n"

    return output


@mcp.tool()
async def fuzz_pipe_connect(pipe_name: str, data: str,
                            timeout: int = 5000) -> str:
    """Connect to a named pipe, send data, and receive response.

    Args:
        pipe_name: Name of the pipe
        data: Data to send (hex string, e.g. '41414141')
        timeout: Timeout in milliseconds (default 5000)
    """
    try:
        data_bytes = _hex_to_bytes(data)
    except ValueError as e:
        return f"## Error\n\nInvalid hex data: {e}\n"

    try:
        result = ipc_engine.connect_and_send(pipe_name, data_bytes, timeout)
    except Exception as e:
        return f"## Error\n\nFailed to connect: {e}\n"

    output = _fmt_header(f"Pipe Connection: {pipe_name}")
    output += _fmt_dict(result) + "\n"
    return output


@mcp.tool()
async def fuzz_pipe_fuzz(pipe_name: str, seed_data: str,
                         iterations: int = 100,
                         mutation_strategy: str = "all",
                         timeout: int = 5000) -> str:
    """Fuzz a named pipe with mutated inputs, monitor for crashes.

    Args:
        pipe_name: Name of the pipe to fuzz
        seed_data: Seed data as hex string (e.g. '41414141')
        iterations: Number of fuzzing iterations (default 100)
        mutation_strategy: Mutation strategy (bitflip/byteflip/arithmetic/boundary/insert/delete/repeat/format_string/overflow/known_bad/all)
        timeout: Per-iteration timeout in ms (default 5000)
    """
    try:
        seed_bytes = _hex_to_bytes(seed_data)
    except ValueError as e:
        return f"## Error\n\nInvalid hex seed data: {e}\n"

    if iterations < 1:
        iterations = 1
    if iterations > 10000:
        iterations = 10000

    try:
        result = ipc_engine.fuzz_pipe(
            pipe_name, seed_bytes, iterations,
            mutation_strategy, timeout
        )
    except Exception as e:
        return f"## Error\n\nFuzzing failed: {e}\n"

    output = _fmt_header(f"Pipe Fuzzing Results: {pipe_name}")
    output += f"**Strategy**: {mutation_strategy} | **Iterations**: {result['iterations']}\n"
    output += f"**Seed**: `{result['seed_data_hex']}`\n\n"

    output += "### Statistics\n"
    output += _fmt_dict(result["stats"]) + "\n\n"

    if result["crashes"]:
        output += f"### Crashes ({len(result['crashes'])})\n"
        for crash in result["crashes"][:20]:
            output += _fmt_dict(crash) + "\n---\n"

    if result["interesting"]:
        output += f"\n### Interesting Responses ({len(result['interesting'])})\n"
        for item in result["interesting"][:20]:
            output += _fmt_dict(item) + "\n---\n"

    if result["errors"]:
        output += f"\n### Errors ({len(result['errors'])})\n"
        for err in result["errors"][:10]:
            output += _fmt_dict(err) + "\n---\n"

    return output


# ============================================================
# IOCTL Tools
# ============================================================

@mcp.tool()
async def fuzz_ioctl_enum() -> str:
    """Enumerate device objects and symbolic links (\\\\.\\DeviceName)."""
    try:
        devices = ioctl_engine.enumerate_devices()
    except Exception as e:
        return f"## Error\n\nFailed to enumerate devices: {e}\n"

    output = _fmt_header("Device Enumeration")
    output += f"**Total devices found**: {len(devices)}\n\n"

    # Group by type
    by_type = {}
    for d in devices:
        t = d.get("type", "unknown")
        by_type.setdefault(t, []).append(d)

    for dtype, items in sorted(by_type.items()):
        output += f"### {dtype.upper()} ({len(items)})\n"
        rows = []
        for d in items[:100]:
            rows.append((d["name"], d["path"], d.get("target", "")[:80]))
        output += _fmt_table(["Name", "Path", "Target"], rows)
        if len(items) > 100:
            output += f"_... and {len(items) - 100} more_\n"
        output += "\n"

    return output


@mcp.tool()
async def fuzz_ioctl_send(device_path: str, ioctl_code: str,
                          input_buffer: str = "",
                          output_size: int = 4096,
                          timeout: int = 5000) -> str:
    """Send a single IOCTL to a device driver.

    Args:
        device_path: Device path (e.g. '\\\\.\\MyDevice')
        ioctl_code: IOCTL control code (int or hex string, e.g. '0x22000C')
        input_buffer: Input data as hex string (e.g. '41414141')
        output_size: Expected output buffer size (default 4096)
        timeout: Timeout in milliseconds (default 5000)
    """
    try:
        in_buf = _hex_to_bytes(input_buffer) if input_buffer else b""
    except ValueError as e:
        return f"## Error\n\nInvalid hex input buffer: {e}\n"

    try:
        code = _parse_int(ioctl_code)
    except ValueError as e:
        return f"## Error\n\nInvalid IOCTL code: {e}\n"

    try:
        result = ioctl_engine.send_ioctl(device_path, code, in_buf,
                                         output_size, timeout)
    except Exception as e:
        return f"## Error\n\nIOCTL send failed: {e}\n"

    output = _fmt_header(f"IOCTL Result: {device_path}")
    output += _fmt_dict(result) + "\n"
    return output


@mcp.tool()
async def fuzz_ioctl_fuzz(device_path: str, ioctl_code: str,
                          seed_buffer: str = "00000000",
                          iterations: int = 100,
                          mutation_strategy: str = "all",
                          timeout: int = 5000) -> str:
    """Fuzz IOCTLs with mutated buffers.

    Args:
        device_path: Device path (e.g. '\\\\.\\MyDevice')
        ioctl_code: IOCTL control code (int or hex string)
        seed_buffer: Seed data as hex string (default '00000000')
        iterations: Number of iterations (default 100)
        mutation_strategy: Mutation strategy (default 'all')
        timeout: Per-iteration timeout in ms (default 5000)
    """
    try:
        seed_bytes = _hex_to_bytes(seed_buffer)
    except ValueError as e:
        return f"## Error\n\nInvalid hex seed buffer: {e}\n"

    try:
        code = _parse_int(ioctl_code)
    except ValueError as e:
        return f"## Error\n\nInvalid IOCTL code: {e}\n"

    if iterations < 1:
        iterations = 1
    if iterations > 10000:
        iterations = 10000

    try:
        result = ioctl_engine.fuzz_ioctl(
            device_path, code, seed_bytes,
            iterations, mutation_strategy, timeout
        )
    except Exception as e:
        return f"## Error\n\nIOCTL fuzzing failed: {e}\n"

    output = _fmt_header(f"IOCTL Fuzzing Results: {device_path}")
    output += f"**IOCTL**: `{result['ioctl_code']}` | **Strategy**: {mutation_strategy}\n"
    output += f"**Iterations**: {result['iterations']} | **Seed**: `{result['seed_hex']}`\n\n"

    output += "### Statistics\n"
    output += _fmt_dict(result["stats"]) + "\n\n"

    if result["crashes"]:
        output += f"### CRASHES ({len(result['crashes'])})\n"
        for crash in result["crashes"][:20]:
            output += _fmt_dict(crash) + "\n---\n"

    if result["interesting"]:
        output += f"\n### Interesting Results ({len(result['interesting'])})\n"
        for item in result["interesting"][:20]:
            output += _fmt_dict(item) + "\n---\n"

    if result["errors"]:
        output += f"\n### Errors ({len(result['errors'])})\n"
        for err in result["errors"][:10]:
            output += _fmt_dict(err) + "\n---\n"

    return output


@mcp.tool()
async def fuzz_ioctl_dacl(device_path: str) -> str:
    """Check security descriptor/DACL of a device object.

    Args:
        device_path: Device path (e.g. '\\\\.\\MyDevice' or just 'MyDevice')
    """
    try:
        result = ioctl_engine.get_device_dacl(device_path)
    except Exception as e:
        return f"## Error\n\nFailed to get device DACL: {e}\n"

    output = _fmt_header(f"Device DACL: {device_path}")
    output += _fmt_dict(result) + "\n"

    if result.get("sddl"):
        output += "\n### SDDL Breakdown\n"
        output += f"```\n{result['sddl']}\n```\n"
        output += "\n_Parse SDDL: O=Owner, G=Group, D=DACL_\n"
        output += "_ACE: (type;flags;rights;object_guid;inherit_guid;sid)_\n"

    return output


@mcp.tool()
async def fuzz_ioctl_bruteforce(device_path: str,
                                ioctl_range_start: str = "0x00000000",
                                ioctl_range_end: str = "0x00100000",
                                timeout: int = 5000) -> str:
    """Bruteforce valid IOCTL codes by sending empty buffers.

    Args:
        device_path: Device path
        ioctl_range_start: Start of IOCTL range (hex, default 0x00000000)
        ioctl_range_end: End of IOCTL range (hex, default 0x00100000)
        timeout: Timeout in ms (default 5000)
    """
    try:
        start = _parse_int(ioctl_range_start)
        end = _parse_int(ioctl_range_end)
    except ValueError as e:
        return f"## Error\n\nInvalid range: {e}\n"

    if end - start > 0x01000000:
        return ("## Error\n\nRange too large (max 0x01000000 codes). "
                "Narrow your range.\n")

    try:
        result = ioctl_engine.bruteforce_ioctls(device_path, start, end, timeout)
    except Exception as e:
        return f"## Error\n\nBruteforce failed: {e}\n"

    output = _fmt_header(f"IOCTL Bruteforce: {device_path}")
    output += f"**Range**: {result['range']} | **Codes tested**: {result['total_codes']}\n\n"

    if result.get("error"):
        output += f"**Error**: {result['error']}\n\n"

    if result["valid_codes"]:
        output += f"### Valid IOCTL Codes ({len(result['valid_codes'])})\n"
        for code in result["valid_codes"]:
            output += _fmt_dict(code) + "\n---\n"

    if result["access_denied_codes"]:
        output += f"\n### Access Denied Codes ({len(result['access_denied_codes'])})\n"
        output += "_These IOCTLs exist but require higher privileges._\n\n"
        for code in result["access_denied_codes"][:50]:
            output += f"- `{code['code']}` ({code['components']['method']})\n"
        if len(result["access_denied_codes"]) > 50:
            output += f"_... and {len(result['access_denied_codes']) - 50} more_\n"

    if not result["valid_codes"] and not result["access_denied_codes"]:
        output += "_No valid IOCTL codes found in the specified range._\n"

    return output


# ============================================================
# COM Tools
# ============================================================

@mcp.tool()
async def fuzz_com_enum(filter: str = "") -> str:
    """Enumerate COM classes (CLSID registry scan).

    Args:
        filter: Optional filter string to search by name or CLSID (default: empty = all)
    """
    try:
        classes = com_engine.enumerate_com_classes(
            filter_str=filter if filter else None,
            max_results=500
        )
    except Exception as e:
        return f"## Error\n\nFailed to enumerate COM classes: {e}\n"

    output = _fmt_header("COM Class Enumeration")
    if filter:
        output += f"**Filter**: `{filter}`\n"
    output += f"**Results**: {len(classes)}\n\n"

    if classes:
        rows = []
        for c in classes[:200]:
            server = c.get("inproc_server") or c.get("local_server") or ""
            if len(server) > 60:
                server = "..." + server[-57:]
            rows.append((
                c["clsid"],
                c["name"][:40] if c["name"] else "",
                c.get("progid") or "",
                server,
                c.get("threading_model") or "",
            ))
        output += _fmt_table(
            ["CLSID", "Name", "ProgID", "Server", "Threading"],
            rows
        )
        if len(classes) > 200:
            output += f"\n_... and {len(classes) - 200} more_\n"

    return output


@mcp.tool()
async def fuzz_com_inspect(clsid_or_progid: str) -> str:
    """Get TypeLib info, interfaces, and methods for a COM object.

    Args:
        clsid_or_progid: CLSID (e.g. '{...}') or ProgID (e.g. 'Shell.Application')
    """
    try:
        result = com_engine.inspect_com_object(clsid_or_progid)
    except Exception as e:
        return f"## Error\n\nFailed to inspect COM object: {e}\n"

    output = _fmt_header(f"COM Object: {clsid_or_progid}")

    output += "### General Info\n"
    output += f"- **CLSID**: `{result.get('clsid')}`\n"
    output += f"- **ProgID**: `{result.get('progid')}`\n"
    output += f"- **Name**: {result.get('name')}\n"

    if result.get("server_info"):
        output += "\n### Server Info\n"
        output += _fmt_dict(result["server_info"]) + "\n"

    if result.get("typelib_info"):
        output += "\n### TypeLib\n"
        output += _fmt_dict(result["typelib_info"]) + "\n"

    if result.get("interfaces"):
        output += "\n### Interfaces\n"
        for iface in result["interfaces"]:
            output += _fmt_dict(iface) + "\n"

    if result.get("methods"):
        output += f"\n### Methods ({len(result['methods'])})\n"
        rows = [(m.get("name"), m.get("memid"), m.get("params"),
                 m.get("invoke_kind", "")) for m in result["methods"]]
        output += _fmt_table(["Name", "MemID", "Params", "InvokeKind"], rows)

    if result.get("properties"):
        output += f"\n### Properties ({len(result['properties'])})\n"
        rows = [(p.get("name"), p.get("memid")) for p in result["properties"]]
        output += _fmt_table(["Name", "MemID"], rows)

    if result.get("error"):
        output += f"\n### Notes\n{result['error']}\n"

    return output


@mcp.tool()
async def fuzz_com_invoke(clsid_or_progid: str, method_name: str,
                          args: str = "[]") -> str:
    """Invoke a method on a COM object.

    Args:
        clsid_or_progid: CLSID or ProgID
        method_name: Method name to invoke
        args: JSON array of arguments (default '[]')
    """
    try:
        parsed_args = json.loads(args)
        if not isinstance(parsed_args, list):
            parsed_args = [parsed_args]
    except json.JSONDecodeError as e:
        return f"## Error\n\nInvalid JSON args: {e}\n"

    try:
        result = com_engine.invoke_com_method(
            clsid_or_progid, method_name, parsed_args
        )
    except Exception as e:
        return f"## Error\n\nCOM invocation failed: {e}\n"

    output = _fmt_header(f"COM Invoke: {clsid_or_progid}.{method_name}")
    output += _fmt_dict(result) + "\n"
    return output


# ============================================================
# RPC Tools
# ============================================================

@mcp.tool()
async def fuzz_rpc_enum(target: str = "127.0.0.1") -> str:
    """Enumerate RPC endpoints (rpcdump-style enumeration).

    Args:
        target: Target host (default '127.0.0.1')
    """
    try:
        result = rpc_engine.enumerate_rpc_endpoints(target)
    except Exception as e:
        return f"## Error\n\nRPC enumeration failed: {e}\n"

    output = _fmt_header(f"RPC Endpoints: {target}")
    output += f"**Method**: {result.get('method', 'unknown')}\n"
    output += f"**Endpoints found**: {len(result.get('endpoints', []))}\n\n"

    if result.get("error"):
        output += f"**Error**: {result['error']}\n\n"

    endpoints = result.get("endpoints", [])
    if endpoints:
        for ep in endpoints[:100]:
            output += "---\n"
            output += _fmt_dict(ep) + "\n"
        if len(endpoints) > 100:
            output += f"\n_... and {len(endpoints) - 100} more_\n"
    else:
        output += "_No endpoints found._\n"

    return output


# ============================================================
# Mutation Engine
# ============================================================

@mcp.tool()
async def fuzz_mutate(data: str, strategy: str = "all",
                      count: int = 10) -> str:
    """Generate mutated versions of input data.

    Args:
        data: Input data as hex string (e.g. '41414141')
        strategy: Mutation strategy (bitflip/byteflip/arithmetic/boundary/insert/delete/repeat/format_string/overflow/known_bad/all)
        count: Number of mutations to generate (default 10, max 1000)
    """
    try:
        data_bytes = _hex_to_bytes(data)
    except ValueError as e:
        return f"## Error\n\nInvalid hex data: {e}\n"

    if count < 1:
        count = 1
    if count > 1000:
        count = 1000

    try:
        mutations = mutation_engine.mutate(
            data_bytes, strategy=strategy, count=count
        )
    except ValueError as e:
        return f"## Error\n\n{e}\n"
    except Exception as e:
        return f"## Error\n\nMutation failed: {e}\n"

    output = _fmt_header("Mutation Results")
    output += f"**Input**: `{data_bytes.hex()}`\n"
    output += f"**Strategy**: {strategy} | **Count**: {len(mutations)}\n\n"

    output += "### Available Strategies\n"
    output += ", ".join(f"`{s}`" for s in mutation_engine.ALL_STRATEGIES) + "\n\n"

    output += "### Mutations\n"
    rows = []
    for i, m in enumerate(mutations[:200]):
        hex_str = m.hex()
        if len(hex_str) > 120:
            hex_str = hex_str[:120] + "..."
        rows.append((i, len(m), hex_str))
    output += _fmt_table(["#", "Size", "Hex"], rows)

    if len(mutations) > 200:
        output += f"\n_... and {len(mutations) - 200} more_\n"

    return output


# ============================================================
# Crash Monitoring
# ============================================================

@mcp.tool()
async def fuzz_monitor_start(process_name: str = "") -> str:
    """Start monitoring for crashes (WER + Event Log).

    Args:
        process_name: Process name to filter for (optional, empty = all)
    """
    try:
        result = monitor_engine.start_monitoring(
            process_name if process_name else None
        )
    except Exception as e:
        return f"## Error\n\nFailed to start monitoring: {e}\n"

    output = _fmt_header("Crash Monitor Started")
    output += _fmt_dict(result) + "\n"
    return output


@mcp.tool()
async def fuzz_monitor_check() -> str:
    """Check for new crashes since monitoring started."""
    try:
        result = monitor_engine.check_crashes()
    except Exception as e:
        return f"## Error\n\nFailed to check crashes: {e}\n"

    if result.get("error"):
        return f"## Error\n\n{result['error']}\n"

    output = _fmt_header("Crash Monitor Check")
    output += f"**Monitoring since**: {result.get('monitoring_since')}\n"
    output += f"**Process filter**: {result.get('process_name')}\n"
    output += f"**Total new crashes**: {result.get('total_new_crashes', 0)}\n\n"

    if result.get("new_wer_dumps"):
        output += f"### New WER Dumps ({len(result['new_wer_dumps'])})\n"
        for dump in result["new_wer_dumps"]:
            output += _fmt_dict(dump) + "\n---\n"

    if result.get("event_log_crashes"):
        output += f"### Event Log Crashes ({len(result['event_log_crashes'])})\n"
        for event in result["event_log_crashes"]:
            output += _fmt_dict(event) + "\n---\n"

    if not result.get("new_wer_dumps") and not result.get("event_log_crashes"):
        output += "_No new crashes detected._\n"

    return output


@mcp.tool()
async def fuzz_monitor_stop() -> str:
    """Stop monitoring and return crash summary."""
    try:
        result = monitor_engine.stop_monitoring()
    except Exception as e:
        return f"## Error\n\nFailed to stop monitoring: {e}\n"

    if result.get("error"):
        return f"## Error\n\n{result['error']}\n"

    output = _fmt_header("Crash Monitor Summary")
    output += f"**Duration**: {result.get('duration_seconds', 0):.1f}s\n"
    output += f"**Process**: {result.get('process_name')}\n"
    output += f"**Total crashes found**: {result.get('total_crashes_found', 0)}\n\n"

    if result.get("crashes"):
        output += "### Crash Details\n"
        for crash in result["crashes"][:50]:
            output += _fmt_dict(crash) + "\n---\n"

    return output


# ============================================================
# PoC Generation
# ============================================================

@mcp.tool()
async def poc_generate(vuln_type: str, target_info: str = "{}") -> str:
    """Generate PoC code based on vulnerability type.

    Args:
        vuln_type: Vulnerability type (ioctl/pipe/com/privesc/race_condition)
        target_info: JSON object with target details for template substitution
    """
    template_map = {
        "ioctl": "ioctl_poc.py.template",
        "pipe": "pipe_poc.py.template",
        "com": "com_poc.py.template",
        "privesc": "privesc_poc.py.template",
        "race_condition": "race_condition_poc.py.template",
    }

    if vuln_type not in template_map:
        return (f"## Error\n\nUnknown vuln_type: `{vuln_type}`\n"
                f"Available: {', '.join(template_map.keys())}\n")

    template_file = os.path.join(TEMPLATES_DIR, template_map[vuln_type])

    try:
        with open(template_file, "r", encoding="utf-8") as f:
            template = f.read()
    except FileNotFoundError:
        return f"## Error\n\nTemplate not found: {template_file}\n"
    except Exception as e:
        return f"## Error\n\nFailed to read template: {e}\n"

    # Apply substitutions from target_info
    try:
        info = json.loads(target_info) if isinstance(target_info, str) else target_info
    except json.JSONDecodeError:
        info = {}

    for key, value in info.items():
        placeholder = "{{" + key.upper() + "}}"
        template = template.replace(placeholder, str(value))

    output = _fmt_header(f"PoC Template: {vuln_type}")
    output += f"**Template**: `{template_map[vuln_type]}`\n\n"
    output += "```python\n"
    output += template
    output += "\n```\n"
    output += ("\n_Note: Replace remaining `{{...}}` placeholders "
               "with actual values before running._\n")

    return output


@mcp.tool()
async def poc_list_templates() -> str:
    """List available PoC templates."""
    output = _fmt_header("Available PoC Templates")

    templates = {
        "ioctl": {
            "file": "ioctl_poc.py.template",
            "description": "IOCTL exploitation PoC - sends crafted IOCTL to a device driver",
            "placeholders": "TARGET_NAME, DEVICE_PATH, IOCTL_CODE, DESCRIPTION, PAYLOAD, PAYLOAD_DESCRIPTION",
        },
        "pipe": {
            "file": "pipe_poc.py.template",
            "description": "Named Pipe exploitation PoC - sends crafted data to a pipe",
            "placeholders": "TARGET_NAME, PIPE_NAME, DESCRIPTION, PAYLOAD, PAYLOAD_DESCRIPTION",
        },
        "com": {
            "file": "com_poc.py.template",
            "description": "COM object exploitation PoC - invokes methods with malicious args",
            "placeholders": "TARGET_NAME, CLSID, METHOD_NAME, DESCRIPTION, ARGS, PAYLOAD_DESCRIPTION",
        },
        "privesc": {
            "file": "privesc_poc.py.template",
            "description": "Privilege escalation PoC - exploits a priv esc vector",
            "placeholders": "TARGET_NAME, VECTOR, DESCRIPTION, EXPLOIT_DESCRIPTION, EXPLOIT_CODE",
        },
        "race_condition": {
            "file": "race_condition_poc.py.template",
            "description": "TOCTOU/Race condition PoC - multi-threaded race exploitation",
            "placeholders": "TARGET_NAME, VECTOR, DESCRIPTION, TARGET_PATH, NUM_THREADS, ITERATIONS, RACE_ACTION_DESCRIPTION, RACE_ACTION, SUCCESS_CHECK_DESCRIPTION, SUCCESS_CHECK",
        },
    }

    for name, info in templates.items():
        output += f"\n### `{name}`\n"
        output += f"- **File**: `{info['file']}`\n"
        output += f"- **Description**: {info['description']}\n"
        output += f"- **Placeholders**: {info['placeholders']}\n"
        # Check file exists
        path = os.path.join(TEMPLATES_DIR, info["file"])
        exists = os.path.isfile(path)
        output += f"- **Status**: {'exists' if exists else 'MISSING'}\n"

    output += "\n### Usage\n"
    output += ("Call `poc_generate(vuln_type, target_info)` with a JSON object "
               "containing placeholder values.\n")
    output += "\nExample:\n```json\n"
    output += json.dumps({
        "target_name": "MyDriver",
        "device_path": r"\\.\\MyDevice",
        "ioctl_code": "0x22000C",
        "description": "Buffer overflow in IOCTL handler",
        "payload": 'b"A" * 4096',
        "payload_description": "Oversized buffer to trigger overflow",
    }, indent=2)
    output += "\n```\n"

    return output


# ============================================================
# Entry point
# ============================================================

if __name__ == "__main__":
    mcp.run()
