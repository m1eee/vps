#!/usr/bin/env python3
"""B global AI routing, C encrypted exit, and A subscription."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import uuid
import yaml

ROOT = Path(__file__).resolve().parent
STATE = ROOT / ".state"
GEN = ROOT / ".generated"
FIELDS = {"DOMAIN": "domain", "DOMAIN-SUFFIX": "domain_suffix", "DOMAIN-KEYWORD": "domain_keyword", "IP-CIDR": "ip_cidr", "IP-CIDR6": "ip_cidr"}

def write(path, content, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)

def settings():
    return json.loads((ROOT / "settings.json").read_text())

def credentials():
    STATE.mkdir(mode=0o700, exist_ok=True)
    STATE.chmod(0o700)
    path = STATE / "secrets.json"
    if not path.exists():
        write(path, json.dumps({
            "uuid": str(uuid.uuid4()),
            "c_password": base64.b64encode(os.urandom(32)).decode(),
            "token": secrets.token_urlsafe(24),
        }, indent=2) + "\n")
    return json.loads(path.read_text())

def import_rules(source):
    config = yaml.safe_load(Path(source).read_text(encoding="utf-8-sig"))
    lines = [line for line in config["rules"] if len(line.split(",")) >= 3 and line.split(",")[2].strip() == "AI"]
    compile_rules(lines)
    text = "\n".join(lines) + "\n"
    write(ROOT / "rules/ai.clash.txt", text, 0o644)
    write(ROOT / "rules/manifest.json", json.dumps({
        "count": len(lines), "sha256": hashlib.sha256(text.encode()).hexdigest(),
        "source": "All AI policy entries from the supplied clash_config, unchanged",
    }, indent=2) + "\n", 0o644)
    print(f"Imported {len(lines)} original AI rules, unchanged")

def compile_rules(lines):
    converted = []
    for line in lines:
        parts = [part.strip() for part in line.split(",")]
        if len(parts) not in (3, 4) or parts[2] != "AI" or parts[0] not in FIELDS:
            raise ValueError("Unsupported AI rule: " + line)
        converted.append({FIELDS[parts[0]]: [parts[1]]})
    return {"version": 3, "rules": converted}

def render():
    s, k = settings(), credentials()
    GEN.mkdir(mode=0o700, exist_ok=True)
    GEN.chmod(0o700)
    lines = (ROOT / "rules/ai.clash.txt").read_text().splitlines()
    write(GEN / "ai.json", json.dumps(compile_rules(lines), indent=2) + "\n")
    b = {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"type": "udp", "tag": "dns-b", "server": "8.8.8.8", "bind_interface": "ens17"},
                {"type": "fakeip", "tag": "ai-fakeip", "inet4_range": "198.18.0.0/15"},
            ],
            "rules": [{"rule_set": ["ai"], "query_type": ["A", "AAAA"], "action": "route", "server": "ai-fakeip"}],
            "final": "dns-b", "strategy": "ipv4_only", "reverse_mapping": True,
        },
        "inbounds": [
            {"type": "tun", "tag": "system-tun", "interface_name": "vpn-tun",
             "address": ["172.19.0.1/30"], "mtu": 1500, "stack": "system",
             "auto_route": True, "auto_redirect": True, "dns_mode": "hijack",
             "route_exclude_address": [s["c_ip"] + "/32", "161.114.115.0/24"]},
            {"type": "vless", "tag": "from-a", "listen": "127.0.0.1", "listen_port": 18080,
             "users": [{"name": "a", "uuid": k["uuid"]}],
             "transport": {"type": "ws", "path": "/vpn"}},
            {"type": "mixed", "tag": "local-test", "listen": "127.0.0.1", "listen_port": 1080},
        ],
        "outbounds": [
            {"type": "direct", "tag": "b-exit", "bind_interface": "ens17",
             "domain_resolver": {"server": "dns-b", "strategy": "ipv4_only"}},
            {"type": "shadowsocks", "tag": "c-exit", "server": s["c_ip"], "server_port": 443,
             "method": "2022-blake3-aes-256-gcm", "password": k["c_password"], "bind_interface": "ens17"},
        ],
        "route": {
            "auto_detect_interface": True,
            "default_domain_resolver": {"server": "dns-b", "strategy": "ipv4_only"},
            "rule_set": [{"type": "local", "tag": "ai", "format": "source", "path": str(GEN / "ai.json")}],
            "rules": [
                {"inbound": ["system-tun"], "port": 53, "action": "hijack-dns"},
                {"port": [80, 443], "action": "sniff",
                 "sniffer": ["http", "tls", "quic"], "timeout": "100ms"},
                {"rule_set": ["ai"], "action": "route", "outbound": "c-exit"},
            ],
            "final": "b-exit",
        },
        "experimental": {"cache_file": {"enabled": True, "path": str(STATE / "cache.db"), "store_fakeip": True}},
    }
    c = {
        "log": {"level": "info", "timestamp": True},
        "dns": {"servers": [{"type": "udp", "tag": "dns-c", "server": "8.8.8.8"}], "strategy": "ipv4_only"},
        "inbounds": [{"type": "shadowsocks", "tag": "from-b", "listen": "0.0.0.0", "listen_port": 443,
                      "method": "2022-blake3-aes-256-gcm", "password": k["c_password"]}],
        "outbounds": [{"type": "direct", "tag": "c-exit", "domain_resolver": {"server": "dns-c", "strategy": "ipv4_only"}}],
        "route": {"final": "c-exit"},
    }
    a = {
        "mixed-port": 7890, "allow-lan": False, "mode": "rule", "log-level": "warning",
        "unified-delay": True, "ipv6": False,
        "dns": {"enable": True, "listen": "127.0.0.1:1053", "ipv6": False,
                "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
                "nameserver": ["https://1.1.1.1/dns-query"], "respect-rules": True,
                "proxy-server-nameserver": ["8.8.8.8", "223.5.5.5"]},
        "tun": {"enable": True, "stack": "system", "auto-route": True, "auto-detect-interface": True,
                "dns-hijack": ["any:53", "tcp://any:53"], "route-exclude-address": [s["b_ip"] + "/32"]},
        "proxies": [{"name": "B", "type": "vless", "server": s["b_ip"], "port": 443,
                     "uuid": k["uuid"], "tls": True, "servername": s["b_ip"], "skip-cert-verify": False,
                     "network": "ws", "udp": True, "packet-encoding": "xudp",
                     "ws-opts": {"path": "/vpn", "headers": {"Host": s["b_ip"]}}}],
        "proxy-groups": [{"name": "VPN", "type": "select", "proxies": ["B"]}],
        "rules": ["MATCH,VPN"],
    }
    for name, config in [("b.json", b), ("c.json", c)]:
        write(GEN / name, json.dumps(config, indent=2) + "\n")
    write(GEN / "clash.yaml", yaml.safe_dump(a, allow_unicode=True, sort_keys=False))
    ip, token = s["b_ip"], k["token"]
    nginx = f"""
server {{
    listen 80;
    server_name {ip};
    location ^~ /.well-known/acme-challenge/ {{ root /var/www/html; }}
    location / {{ return 404; }}
}}
server {{
    listen 443 ssl;
    server_name {ip};
    ssl_certificate /etc/letsencrypt/live/private-vpn/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/private-vpn/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    access_log off;
    location = /vpn {{
        proxy_pass http://127.0.0.1:18080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }}
    location = /sub/{token}/clash.yaml {{
        alias /var/lib/private-vpn/clash.yaml;
        default_type application/yaml;
        add_header Cache-Control "private, no-store" always;
        add_header profile-update-interval 12;
    }}
    location = /sub/{token}/ai.txt {{
        alias /var/lib/private-vpn/ai.clash.txt;
        default_type text/plain;
        add_header Cache-Control "private, no-store" always;
    }}
    location / {{ return 404; }}
}}
"""
    write(GEN / "nginx.conf", nginx.lstrip())
    write(STATE / "subscription.url", f"https://{ip}/sub/{token}/clash.yaml\n")
    print(f"Rendered B global TUN + C exit + A single-node subscription; AI rules={len(lines)}")

def run(*command):
    subprocess.run(list(command), check=True)

def publish():
    import grp
    group = grp.getgrnam("www-data").gr_gid
    directory = Path("/var/lib/private-vpn")
    directory.mkdir(mode=0o750, parents=True, exist_ok=True)
    directory.chmod(0o750)
    os.chown(directory, 0, group)
    for source, name in [(GEN / "clash.yaml", "clash.yaml"), (ROOT / "rules/ai.clash.txt", "ai.clash.txt")]:
        write(directory / name, source.read_text(), 0o640)
        os.chown(directory / name, 0, group)
    write("/etc/nginx/sites-available/private-vpn", (GEN / "nginx.conf").read_text())
    default = Path("/etc/nginx/sites-enabled/default")
    if default.is_symlink():
        default.unlink()
    enabled = Path("/etc/nginx/sites-enabled/private-vpn")
    if not enabled.exists():
        enabled.symlink_to("/etc/nginx/sites-available/private-vpn")
    run("nginx", "-t")
    run("systemctl", "reload", "nginx")
    print("HTTPS subscription published")

def unit(command, description, working=""):
    return f"""[Unit]
Description={description}
After=network-online.target systemd-resolved.service
Wants=network-online.target
[Service]
Type=simple
{working}ExecStart={command}
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
"""

def deploy():
    render()
    run("sing-box", "check", "-c", str(GEN / "b.json"))
    host = settings()["c_ssh"]
    options = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15"]
    c_unit = unit("/usr/local/bin/sing-box run -c /etc/private-vpn/c.json", "Private VPN C exit")
    write(GEN / "private-vpn-c.service", c_unit)
    for source, destination in [
        (Path("/usr/local/bin/sing-box"), "/tmp/private-vpn-sing-box"),
        (GEN / "c.json", "/tmp/private-vpn-c.json"),
        (GEN / "private-vpn-c.service", "/tmp/private-vpn-c.service"),
    ]:
        run("scp", "-q", "-C", *options, str(source), host + ":" + destination)
    remote = "set -e; install -m 755 /tmp/private-vpn-sing-box /usr/local/bin/sing-box; install -d -m 700 /etc/private-vpn; install -m 600 /tmp/private-vpn-c.json /etc/private-vpn/c.json; install -m 644 /tmp/private-vpn-c.service /etc/systemd/system/private-vpn-c.service; /usr/local/bin/sing-box check -c /etc/private-vpn/c.json; systemctl daemon-reload; systemctl enable private-vpn-c; systemctl restart private-vpn-c; rm -f /tmp/private-vpn-c.json"
    run("ssh", *options, host, remote)
    b_unit = unit(f"/usr/local/bin/sing-box run -c {GEN}/b.json", "Private VPN B global AI routing", f"WorkingDirectory={ROOT}\n")
    write(ROOT / "systemd/private-vpn-b.service", b_unit, 0o644)
    write(ROOT / "systemd/private-vpn-c.service", c_unit, 0o644)
    write("/etc/systemd/system/private-vpn-b.service", b_unit, 0o644)
    renewal = f"""[Unit]
Description=Renew the private VPN public IP certificate
After=network-online.target
[Service]
Type=oneshot
ExecStart={STATE}/certbot/bin/certbot renew --quiet --deploy-hook "/usr/sbin/nginx -s reload"
"""
    timer = """[Unit]
Description=Check the short-lived IP certificate twice daily
[Timer]
OnCalendar=*-*-* 03,15:00:00
RandomizedDelaySec=1800
Persistent=true
[Install]
WantedBy=timers.target
"""
    for name, content in [("private-vpn-renew.service", renewal), ("private-vpn-renew.timer", timer)]:
        write(ROOT / "systemd" / name, content, 0o644)
        write(Path("/etc/systemd/system") / name, content, 0o644)
    run("systemctl", "daemon-reload")
    run("systemctl", "enable", "private-vpn-b", "private-vpn-renew.timer")
    publish()
    run("systemctl", "start", "private-vpn-renew.timer")
    run("systemd-run", "--unit=private-vpn-rollback", "--on-active=180s", "/usr/bin/systemctl", "stop", "private-vpn-b")
    run("systemctl", "restart", "private-vpn-b")
    print("B global routing enabled. After checking a new SSH connection, cancel private-vpn-rollback.timer")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["init", "render", "publish", "deploy", "links", "status"])
    parser.add_argument("--source", type=Path)
    args = parser.parse_args()
    if args.command == "init":
        credentials()
        if args.source or not (ROOT / "rules/ai.clash.txt").exists():
            import_rules(args.source or ROOT / "clash_config")
        render()
    elif args.command == "render":
        render()
    elif args.command == "publish":
        publish()
    elif args.command == "deploy":
        deploy()
    elif args.command == "links":
        print((STATE / "subscription.url").read_text().strip())
    else:
        run("systemctl", "status", "private-vpn-b", "nginx", "--no-pager")

if __name__ == "__main__":
    main()
