# 私人 VPN

A（本机）→ B（161.114.115.165）为 VLESS + WebSocket + HTTPS；B → C（38.46.155.57）为 Shadowsocks 2022，支持 TCP/UDP。

B 使用 sing-box 系统 TUN 接管全局流量。原配置全部 AI 规则固定从 C 出口，其他流量从 B 出口。A 只有 MATCH,VPN，不维护 AI 分流规则。规则保存在 rules/ai.clash.txt，原始配置和运行密钥不提交到 Git。

项目位于 B 的 /root/workspace/vpn。Python 依赖 PyYAML，服务依赖 sing-box 1.14.2、nginx、nftables、systemd-resolved。HTTPS 使用 Let's Encrypt 的公网 IP 证书，无需域名；systemd 定时续期。

```sh
cd /root/workspace/vpn
python3 vpnctl.py init --source clash_config
python3 vpnctl.py deploy
# 新 SSH 连接正常后取消首次启动的回滚
systemctl stop private-vpn-rollback.timer
python3 vpnctl.py links
```

在 Clash Verge 的订阅中导入 links 输出的地址，启用 TUN。订阅地址包含访问令牌，请妥善保存。

```sh
python3 vpnctl.py status
journalctl -u private-vpn-b -n 30 --no-pager
ssh vps57 systemctl status private-vpn-c --no-pager
systemctl list-timers private-vpn-renew.timer
```

更新原规则后再次运行 init --source clash_config、deploy。渲染配置和密钥分别在 .generated/、.state/ 中，只留在服务器。停止 B 全局分流：systemctl stop private-vpn-b；恢复：systemctl start private-vpn-b。

分流依据域名，使用选择性 fake-IP DNS 和 HTTP/TLS/QUIC 域名嗅探。使用自定义加密 DNS 加 ECH，或直接连接没有域名信息的裸 IP，可能无法关联已有域名规则。没有新增 AI IP 范围。C 不可用时已匹配 AI 的连接失败，不自动回退 B。

## 环境准备与更新

当前 B/C 已部署 sing-box 1.14.2，并由 systemd 开机启动。B 的网络接口为 ens17；settings.json 中配置 B/C 公网 IP 及 B 上的 C SSH 别名 vps57。

重建时，B 需要安装 python3-yaml、python3-venv、nginx、nftables、systemd-resolved，并将对应平台的 sing-box 1.14.2 安装至 /usr/local/bin/sing-box。B 必须能够通过 SSH 别名 vps57 免密访问 C，deploy 会同步二进制及 C 配置。

IP 证书的初始化命令（B 的公网 TCP 80 应可访问，nginx 的 ACME 根目录为 /var/www/html）：

```sh
python3 -m venv .state/certbot
.state/certbot/bin/pip install certbot==5.8.0
.state/certbot/bin/certbot certonly --webroot -w /var/www/html \
  --ip-address 161.114.115.165 --required-profile shortlived \
  --cert-name private-vpn --key-type ecdsa \
  --agree-tos --register-unsafely-without-email --non-interactive
```

B 对外使用 TCP 443（代理及订阅）和 TCP 80（ACME）；C 使用 TCP/UDP 443（Shadowsocks 2022）。两机原来的 SSH 端口保持不变。IP 证书有效期很短，private-vpn-renew.timer 每日两次检查续期，成功后重新加载 nginx。

常规配置更新使用 render、配置检查、重启 B，再 publish；无需重复上传 C 二进制：

```sh
python3 vpnctl.py render
sing-box check -c .generated/b.json
systemctl restart private-vpn-b
python3 vpnctl.py publish
```

修改 C 配置或初次部署才需要 deploy。部署包含 180 秒自动回滚计时器，确认新 SSH 连接正常后取消计时器。C 故障时不会自动切换 AI 出口；恢复 C 服务后即可恢复连接。

## 已完成的验证

见 verification.md。本机在用的 Clash 未切换配置；订阅由用户导入后选择启用。修改服务器上的规则和配置后，可在 Clash Verge 更新订阅；分流规则由 B 执行。
