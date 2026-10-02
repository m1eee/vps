# 部署验证

日期：2026-10-02。sing-box 1.14.2，A 兼容性检查使用 Mihomo 1.19.10。

| 场景 | 结果 |
| --- | --- |
| 原配置 AI 规则逐行对比 | 全部 42 条一致，保留顺序与值 |
| B 无代理环境访问 claude.ai/cdn-cgi/trace | 出口 38.46.155.57 |
| B 无代理环境访问 www.cloudflare.com/cdn-cgi/trace | 出口 161.114.115.165 |
| B 系统 DNS 查询 claude.ai | 返回 AI fake-IP，TUN DNS 接管正常 |
| B 使用真实 IP、TLS SNI 访问 claude.ai | 出口 38.46.155.57，域名嗅探生效 |
| A 临时独立 Mihomo 进程访问上述两个地址 | 分别为 C、B 出口；进程已退出，未修改在用 Clash |
| A 通过 HTTPS 下载订阅 | 证书校验成功，配置检查通过 |
| 隔离 B 实例将 C 端口设为不可达 | AI 连接失败，普通流量仍从 B 出口 |
| IP 证书续期 dry-run（含 nginx 部署钩子） | 成功 |
| 新 SSH 连接至 B | 正常，首次部署回滚计时器已取消 |

隔离故障测试未停止线上 B/C 服务。A 的订阅规则只有 MATCH,VPN，AI 分流仅发生于 B；B 系统应用与 A 转发连接使用同一套 AI 规则。HTTP/TLS/QUIC 嗅探用于识别已有真实 IP 的连接，不新增域名或 IP 规则。
