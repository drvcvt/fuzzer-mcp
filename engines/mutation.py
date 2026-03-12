"""
Mutation engine for fuzzing inputs.

Provides various mutation strategies for generating test cases
from seed data. All strategies are deterministic when given a seed.
"""

import random
import struct
from typing import List, Optional


# Boundary values commonly triggering bugs
BOUNDARY_VALUES = {
    "byte": [0x00, 0x01, 0x7E, 0x7F, 0x80, 0xFE, 0xFF],
    "word": [0x0000, 0x0001, 0x007F, 0x0080, 0x00FF, 0x0100, 0x7FFE, 0x7FFF,
             0x8000, 0xFFFE, 0xFFFF],
    "dword": [0x00000000, 0x00000001, 0x0000007F, 0x00000080, 0x000000FF,
              0x00000100, 0x0000FFFF, 0x00010000, 0x7FFFFFFE, 0x7FFFFFFF,
              0x80000000, 0xFFFFFFFE, 0xFFFFFFFF],
    "qword": [0x0000000000000000, 0x0000000000000001, 0x000000007FFFFFFF,
              0x0000000080000000, 0x00000000FFFFFFFF, 0x0000000100000000,
              0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0xFFFFFFFFFFFFFFFF],
}

FORMAT_STRINGS = [
    b"%s", b"%x", b"%n", b"%p", b"%d",
    b"%s" * 20, b"%x" * 20, b"%n" * 20, b"%p" * 20,
    b"AAAA%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x",
    b"%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
    b"%n%n%n%n%n%n%n%n%n%n",
    b"%.1024d", b"%.2048d", b"%.4096d",
    b"%99999999s",
]

KNOWN_BAD_VALUES = [
    b"\x00",                          # null byte
    b"\x00" * 4,                      # null dword
    b"..\\..\\..\\..\\..\\",          # path traversal (windows)
    b"../../../../../",               # path traversal (unix-style)
    b"\\\\?\\",                       # NT path prefix
    b"\\\\?\\UNC\\",                  # UNC path prefix
    b"\\Device\\",                    # device path
    b"\\\\.\\",                       # win32 device namespace
    b"CON", b"PRN", b"AUX", b"NUL",  # reserved device names
    b"COM1", b"LPT1",                 # reserved device names
    b"\r\n", b"\n", b"\r",           # line endings
    b"\xff\xfe",                      # BOM UTF-16 LE
    b"\xfe\xff",                      # BOM UTF-16 BE
    b"A" * 260,                       # MAX_PATH
    b"A" * 32768,                     # large buffer
]


def _ensure_bytes(data) -> bytes:
    """Convert input to bytes."""
    if isinstance(data, str):
        try:
            return bytes.fromhex(data)
        except ValueError:
            return data.encode("utf-8")
    if isinstance(data, (list, tuple)):
        return bytes(data)
    return bytes(data)


def mutate_bitflip(data: bytes, rng: random.Random, count: int = 1) -> List[bytes]:
    """Flip random bits in the data."""
    results = []
    for _ in range(count):
        if len(data) == 0:
            results.append(data)
            continue
        mutated = bytearray(data)
        num_flips = rng.randint(1, max(1, len(data) // 4))
        for _ in range(num_flips):
            pos = rng.randint(0, len(mutated) - 1)
            bit = rng.randint(0, 7)
            mutated[pos] ^= (1 << bit)
        results.append(bytes(mutated))
    return results


def mutate_byteflip(data: bytes, rng: random.Random, count: int = 1) -> List[bytes]:
    """Replace random bytes with random values."""
    results = []
    for _ in range(count):
        if len(data) == 0:
            results.append(data)
            continue
        mutated = bytearray(data)
        num_flips = rng.randint(1, max(1, len(data) // 4))
        for _ in range(num_flips):
            pos = rng.randint(0, len(mutated) - 1)
            mutated[pos] = rng.randint(0, 255)
        results.append(bytes(mutated))
    return results


def mutate_arithmetic(data: bytes, rng: random.Random, count: int = 1) -> List[bytes]:
    """Add/subtract small values from bytes, words, or dwords."""
    results = []
    for _ in range(count):
        if len(data) == 0:
            results.append(data)
            continue
        mutated = bytearray(data)
        pos = rng.randint(0, len(mutated) - 1)
        width = rng.choice([1, 2, 4])
        delta = rng.randint(-35, 35)
        if width == 1:
            mutated[pos] = (mutated[pos] + delta) & 0xFF
        elif width == 2 and pos + 1 < len(mutated):
            val = struct.unpack_from("<H", mutated, pos)[0]
            val = (val + delta) & 0xFFFF
            struct.pack_into("<H", mutated, pos, val)
        elif width == 4 and pos + 3 < len(mutated):
            val = struct.unpack_from("<I", mutated, pos)[0]
            val = (val + delta) & 0xFFFFFFFF
            struct.pack_into("<I", mutated, pos, val)
        else:
            mutated[pos] = (mutated[pos] + delta) & 0xFF
        results.append(bytes(mutated))
    return results


def mutate_boundary(data: bytes, rng: random.Random, count: int = 1) -> List[bytes]:
    """Insert boundary values at random positions."""
    results = []
    for _ in range(count):
        if len(data) == 0:
            results.append(data)
            continue
        mutated = bytearray(data)
        width = rng.choice(["byte", "word", "dword"])
        values = BOUNDARY_VALUES[width]
        val = rng.choice(values)
        pos = rng.randint(0, len(mutated) - 1)
        if width == "byte":
            mutated[pos] = val & 0xFF
        elif width == "word" and pos + 1 < len(mutated):
            struct.pack_into("<H", mutated, pos, val & 0xFFFF)
        elif width == "dword" and pos + 3 < len(mutated):
            struct.pack_into("<I", mutated, pos, val & 0xFFFFFFFF)
        else:
            mutated[pos] = val & 0xFF
        results.append(bytes(mutated))
    return results


def mutate_insert(data: bytes, rng: random.Random, count: int = 1) -> List[bytes]:
    """Insert random bytes at random positions."""
    results = []
    for _ in range(count):
        mutated = bytearray(data)
        pos = rng.randint(0, len(mutated))
        length = rng.randint(1, 32)
        insert_data = bytes(rng.randint(0, 255) for _ in range(length))
        mutated[pos:pos] = insert_data
        results.append(bytes(mutated))
    return results


def mutate_delete(data: bytes, rng: random.Random, count: int = 1) -> List[bytes]:
    """Delete random byte ranges."""
    results = []
    for _ in range(count):
        if len(data) <= 1:
            results.append(data)
            continue
        mutated = bytearray(data)
        pos = rng.randint(0, len(mutated) - 1)
        length = rng.randint(1, min(16, len(mutated) - pos))
        del mutated[pos:pos + length]
        results.append(bytes(mutated))
    return results


def mutate_repeat(data: bytes, rng: random.Random, count: int = 1) -> List[bytes]:
    """Repeat sections of the input."""
    results = []
    for _ in range(count):
        if len(data) == 0:
            results.append(data)
            continue
        mutated = bytearray(data)
        pos = rng.randint(0, len(mutated) - 1)
        length = rng.randint(1, min(32, len(mutated) - pos))
        repeats = rng.randint(2, 16)
        section = mutated[pos:pos + length]
        mutated[pos:pos + length] = section * repeats
        results.append(bytes(mutated))
    return results


def mutate_format_string(data: bytes, rng: random.Random, count: int = 1) -> List[bytes]:
    """Insert format string patterns."""
    results = []
    for _ in range(count):
        fmt = rng.choice(FORMAT_STRINGS)
        if len(data) == 0:
            results.append(fmt)
            continue
        mutated = bytearray(data)
        pos = rng.randint(0, len(mutated))
        mutated[pos:pos] = fmt
        results.append(bytes(mutated))
    return results


def mutate_overflow(data: bytes, rng: random.Random, count: int = 1) -> List[bytes]:
    """Generate long strings/buffers for buffer overflow testing."""
    results = []
    lengths = [64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]
    chars = [b"A", b"B", b"\x41", b"\xff", b"\x00"]
    for _ in range(count):
        length = rng.choice(lengths)
        char = rng.choice(chars)
        payload = char * length
        if len(data) > 0:
            # optionally prepend some of the original data
            prefix_len = rng.randint(0, min(16, len(data)))
            payload = data[:prefix_len] + payload
        results.append(payload)
    return results


def mutate_known_bad(data: bytes, rng: random.Random, count: int = 1) -> List[bytes]:
    """Insert known-bad values."""
    results = []
    for _ in range(count):
        bad = rng.choice(KNOWN_BAD_VALUES)
        if len(data) == 0:
            results.append(bad)
            continue
        mutated = bytearray(data)
        pos = rng.randint(0, len(mutated))
        mutated[pos:pos] = bad
        results.append(bytes(mutated))
    return results


# Strategy registry
STRATEGIES = {
    "bitflip": mutate_bitflip,
    "byteflip": mutate_byteflip,
    "arithmetic": mutate_arithmetic,
    "boundary": mutate_boundary,
    "insert": mutate_insert,
    "delete": mutate_delete,
    "repeat": mutate_repeat,
    "format_string": mutate_format_string,
    "overflow": mutate_overflow,
    "known_bad": mutate_known_bad,
}

ALL_STRATEGIES = list(STRATEGIES.keys())


def mutate(data: bytes, strategy: str = "all", count: int = 10,
           seed: Optional[int] = None) -> List[bytes]:
    """
    Generate mutated versions of input data.

    Args:
        data: Input data to mutate
        strategy: Mutation strategy name or "all" for mixed
        count: Number of mutations to generate
        seed: Random seed for deterministic output

    Returns:
        List of mutated byte sequences
    """
    rng = random.Random(seed)

    if strategy == "all":
        results = []
        strategy_names = list(STRATEGIES.keys())
        rng.shuffle(strategy_names)  # Randomize order for unbiased coverage at small counts
        per_strategy = max(1, count // len(STRATEGIES))
        remainder = count - per_strategy * len(STRATEGIES)
        for name in strategy_names:
            func = STRATEGIES[name]
            n = per_strategy + (1 if remainder > 0 else 0)
            remainder -= 1
            results.extend(func(data, rng, n))
        return results[:count]

    if strategy not in STRATEGIES:
        raise ValueError(f"Unknown strategy: {strategy}. Available: {', '.join(STRATEGIES.keys())}")

    return STRATEGIES[strategy](data, rng, count)
