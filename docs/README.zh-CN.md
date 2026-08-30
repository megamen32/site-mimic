# site-mimic

[English](../README.md) · [Русский](README.ru.md) · [HANDOFF](../HANDOFF.md)

> 让 Go HTTP 客户端在传输层呈现出目标网站所期望的真实浏览器身份：TLS
> ClientHello（JA3/JA4）、ALPN、HTTP/2 以及捕获到的请求头集合。Go
> 标准库的 TLS 指纹极易被识别，而 ClientHello 签名正是 DPI 设备最先封杀
> 的对象（TSPU 按 ClientHello/ServerHello 签名封堵——与当年封杀 snowflake
> 是同一机制）。

site-mimic 打包了一套经过生产验证的 uTLS 传输层，以及让“浏览器拟合适配”
可重复执行的方法论：一个引导 AI 智能体从抓包到已验证请求的技能（skill）、
抓包/验证工具链，以及两个完整的实战示例。

## 已验证（2026-08-30，针对 vk.ru）

| 客户端 | JA4（stand 固定版本 Chromium） | 结果 |
|---|---|---|
| uTLS `chrome_auto` | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | 200 OK，HTTP/2；近似匹配（扩展集合略有差异） |
| `chrome_exact`（TLS 委托给 [headless-client](https://github.com/kulikov0/headless-client)） | `t13d1516h2_8daaf6152771_806a8c22fdea` | **JA4 与浏览器逐字节一致** |
| 真实手机（Samsung S21 Ultra，Android Chrome 149，4G） | 同一指纹类别：TLS 1.3、含 GREASE 的 16 个密码套件、ALPN h2、每次连接随机化扩展顺序 | 证实了桌面参考基准 |

另已验证：`stream.wb.ru` 返回与全新真实浏览器完全相同的 498 `wbaas`
反爬挑战——传输层对齐是正确的，JS 挑战属于应用层（见
`examples/stream-wb-ru`）。

## 致谢：headless-client 是更精确的传输层实现

**[kulikov0/headless-client](https://github.com/kulikov0/headless-client)
在传输层做得更好，site-mimic 正是构建于其上。** 它的 ClientHello 是对照
当前稳定版 Chrome 逐项实测的（包括后量子签名算法），因此能与浏览器逐字节
一致；而现成的 uTLS `chrome_auto` 配置略有滞后。它的 HTTP 部分还额外覆盖
了请求头顺序、HTTP/2 SETTINGS 帧结构以及连接复用；它的捕获测试台
（`stand/`）能在链路上将你的二进制与真实 Chromium 做差分对比——这正是我
们现在到处推荐的验证闭环。

site-mimic 自身的价值在于传输层之上的那一层：面向 AI 智能体的“网站适配”
技能、抓包→配置→验证的工具链、网站配置文件与实战示例。
`tls_client_hello: "chrome_exact"` 会将 TLS/HTTP2 层委托给 headless-client
（MIT 协议，致谢），`chrome_auto` 等仍可作为纯 uTLS 的备选。

## 安装

```sh
go get github.com/megamen32/site-mimic/mimic
```

## 几分钟上手

```sh
git clone https://github.com/megamen32/site-mimic && cd site-mimic/examples/vk-ru
go run . -dump ch.json
python3 ../../tools/parse_clienthello.py ch.json   # 我们 ClientHello 的 JA3/JA4
```

预期输出：`status: 200 OK`、`proto: HTTP/2.0`（`server: kittenx`）。之后按
[skill/SKILL.md](../skill/SKILL.md) 适配新网站。

## 了解更多

- [网站适配方法论（AI 智能体技能）](../skill/SKILL.md)
- [工作原理、限制、路线图](methodology.md)
- [HANDOFF —— 已验证状态与待办事项](../HANDOFF.md)
- [vk.ru 示例](../examples/vk-ru/) · [stream.wb.ru 示例](../examples/stream-wb-ru/) · [stand 探针](../examples/stand-probe/)

## 如实说明的限制

使用 `chrome_exact` 时 TLS 层逐字节一致；使用 uTLS 配置时为近似匹配。请求
头的值与集合是精确的，但线上字节顺序与 HTTP/2 SETTINGS 帧结构仍是 Go 默认
实现；QUIC/DTLS 暂未覆盖——详见
[methodology.md](methodology.md)。反爬 JavaScript 挑战在设计上不在范围内。

MIT 许可证。与 VK 或 Wildberries 无关联。
