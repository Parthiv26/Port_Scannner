# Port_Scannner
Port Scanner Using Python Automation

# Python TCP Port Scanner

A small standard-library TCP port scanner for authorized testing.

## Usage

```powershell
python .\port_scanner.py 127.0.0.1
python .\port_scanner.py scanme.nmap.org -p 22,80,443
python .\port_scanner.py https://example.com --cloud-website --show-closed
python .\port_scanner.py 192.168.1.10 -p 1-1024 -t 0.5 -w 200
python .\port_scanner.py 127.0.0.1 -p 1-100 --show-closed
```

## Options

- `host`: target website URL, hostname, or IPv4 address.
- `-p, --ports`: comma-separated ports or ranges. Default: `1-1024`, or common website/cloud ports with `--cloud-website`.
- `-t, --timeout`: connection timeout per port in seconds. Default: `1.0`.
- `-w, --workers`: concurrent worker count. Default: `100`.
- `--show-closed`: print closed, filtered, and unreachable ports as well as open ports.
- `--cloud-website`: scan common website and cloud service ports such as `80`, `443`, `8080`, `8443`, `3306`, `5432`, `6379`, and `27017`.

## Port Status

- `OPEN`: the TCP connection succeeded.
- `CLOSED`: the host responded, but no service accepted the connection.
- `FILTERED`: the connection timed out or the network path appears blocked.
- `UNREACHABLE`: the scanner received another network/socket error.

Only scan systems you own or have explicit permission to test.
