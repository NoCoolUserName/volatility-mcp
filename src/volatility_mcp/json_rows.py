"""Stream Volatility's JSON array without loading an entire analysis into RAM."""
import json
from pathlib import Path


def iter_rows(path: Path, max_record_bytes: int = 16 * 1024 * 1024):
    decoder = json.JSONDecoder()
    with path.open(encoding="utf-8") as stream:
        buffer, eof = "", False
        def more():
            nonlocal buffer, eof
            chunk = stream.read(65536)
            eof = not chunk
            buffer += chunk
        def whitespace():
            nonlocal buffer
            buffer = buffer.lstrip()
            while not buffer and not eof:
                more()
                buffer = buffer.lstrip()
        whitespace()
        if not buffer.startswith("["):
            raise ValueError("expected a JSON row array")
        buffer = buffer[1:]
        first = True
        while True:
            whitespace()
            if buffer.startswith("]"):
                buffer = buffer[1:]
                whitespace()
                if buffer:
                    raise ValueError("data after the JSON array")
                return
            if not first:
                if not buffer.startswith(","):
                    raise ValueError("incomplete JSON array or missing comma")
                buffer = buffer[1:]
                whitespace()
            while True:
                try:
                    row, end = decoder.raw_decode(buffer)
                    break
                except json.JSONDecodeError:
                    if eof:
                        raise ValueError("incomplete JSON record") from None
                    if len(buffer.encode("utf-8")) > max_record_bytes:
                        raise ValueError("individual record exceeds 16 MiB conversion limit; inspect raw output")
                    more()
            if not isinstance(row, dict):
                raise ValueError("expected object rows")
            yield row
            buffer = buffer[end:]
            first = False
