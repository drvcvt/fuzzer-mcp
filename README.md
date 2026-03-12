# fuzzer-mcp

MCP server for fuzzing Windows IPC mechanisms. Covers Named Pipes, IOCTLs, COM objects, and RPC endpoints with mutation-based fuzzing, crash monitoring, and proof-of-concept generation.

## What it does

### Named Pipes
- Enumerate all named pipes on the system
- Query security descriptors and DACLs for individual pipes
- Connect, send data, and capture responses
- Fuzz pipes with mutated inputs across configurable iteration counts

### IOCTL / Device Drivers
- Enumerate device objects and symbolic links
- Send single IOCTLs with custom input buffers
- Fuzz IOCTLs with mutation strategies (bitflip, byteflip, arithmetic, boundary values, format strings, known-bad values)
- Bruteforce valid IOCTL codes across a specified range
- Query device security descriptors and DACLs

### COM Objects
- Enumerate COM classes via CLSID registry scan with optional filtering
- Inspect TypeLib, interfaces, methods, and properties
- Invoke COM methods with arbitrary arguments

### RPC Endpoints
- Enumerate RPC endpoints (rpcdump-style)

### Mutation Engine
- Generate mutated test cases from seed data
- Strategies: bitflip, byteflip, arithmetic, boundary, insert, delete, repeat, format_string, overflow, known_bad, or all combined

### Crash Monitoring
- Monitor for crashes via Windows Error Reporting (WER) dumps and Event Log
- Start/stop monitoring with optional process name filtering
- Collect crash details for analysis

### PoC Generation
- Generate proof-of-concept scripts from templates
- Templates for: IOCTL exploits, pipe exploits, COM exploits, privilege escalation, race conditions (TOCTOU)

## Requirements

- Windows 10/11
- Python 3.10+
- Dependencies: `pip install -r requirements.txt`
  - `comtypes` for COM interaction
  - `pywin32` for Windows API access
  - `impacket` for RPC enumeration

## Setup

```bash
pip install -r requirements.txt
python server.py
```

Some operations (IOCTL access, device enumeration, kernel object queries) may require elevated privileges depending on the target.

## Architecture

```
fuzzer/
  server.py              # MCP server, tool definitions
  engines/
    mutation.py          # Mutation strategies
    ipc.py               # Named pipe operations
    ioctl.py             # IOCTL/device driver operations
    com.py               # COM object enumeration and invocation
    rpc.py               # RPC endpoint enumeration
    monitor.py           # Crash monitoring (WER + Event Log)
  templates/             # PoC code templates
  utils/                 # Shared helpers
```

## License

CC BY-NC-SA 4.0 -- see [LICENSE](LICENSE).
