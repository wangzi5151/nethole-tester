# 安全政策 · Security Policy

## 支持的版本 · Supported versions

安全修复只针对最新发布版本和 `main` 分支。请先升级到最新版再确认问题是否仍存在。

Security fixes are applied to the latest release and to `main`. Please upgrade
to the latest version before reporting.

## 报告漏洞 · Reporting a vulnerability

**请不要**为安全漏洞开公开 Issue（不要在 Issue 里贴可直接利用的细节）。

**Do not** open a public issue for a security vulnerability.

请使用 GitHub 的私密漏洞报告功能：
[Report a vulnerability](https://github.com/wangzi5151/nethole-tester/security/advisories/new)
（仓库页面 `Security` 标签 → `Report a vulnerability`）。

Please use GitHub's private vulnerability reporting:
the repository's **Security** tab → **Report a vulnerability**.

报告时请尽量包含：受影响版本、复现步骤、影响范围。我们会尽快确认并在修复后
致谢报告者（除非你希望匿名）。

Include, where possible: the affected version, reproduction steps, and the
impact. We will acknowledge the report, fix it, and credit the reporter
(unless you prefer to stay anonymous).

## 本工具的安全模型 · Security model

- **零遥测 / 零上传**：程序只发送你配置的 ICMP / TCP / DNS 探测包，所有数据
  只写入你指定的本地目录。任何引入回传逻辑的改动都会被拒绝。
- **保守速率**：探测间隔强制最小 200ms，默认 ≥ 1s；本工具不提供、也不会接受
  压测 / 泛洪 / 攻击类功能。
- **最小权限降级**：ICMP 无法提权时自动降级为 TCP/DNS 并明确提示，不会要求
  或诱导用户关闭系统安全机制。
- **报告即数据**：生成的 HTML 报告是单个离线静态文件，不加载任何远程资源。

- **Zero telemetry, zero upload.** The only network traffic is the probes you
  configure; all data stays in the local output directory you choose.
- **Conservative rates by design.** Minimum probe interval is enforced at
  200ms (≥ 1s by default); stress-testing / flooding features are out of scope
  and will not be accepted.
- **Graceful privilege degradation.** When ICMP needs privileges the tool
  degrades to TCP/DNS with a clear notice instead of asking you to weaken
  system security.
- **Reports are data.** The generated HTML report is a single offline static
  file that loads no remote resources.
