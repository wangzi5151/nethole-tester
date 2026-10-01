# 贡献指南 · Contributing

感谢你愿意一起改进 NetHole-Tester！无论是修 bug、加平台支持，还是改文案，都很欢迎。

## 快速开始

```bash
git clone https://github.com/wangzi5151/nethole-tester
cd nethole-tester
make build      # 本机二进制
make test       # 单元测试（不联网，秒级）
make vet        # 静态检查
```

## 提交前请确认

- [ ] `gofmt -s -w .` 已格式化；
- [ ] `make test` 全部通过；
- [ ] `make vet` 无告警；
- [ ] 新功能有对应测试（网络相关测试用 `testing.Short()` 跳过）；
- [ ] 不引入任何遥测 / 上传 / 第三方运行时依赖（这是硬性红线）。

验证「零回传」：

```bash
grep -rniE "http://|https://|analytics|telemetry|upload" --include=*.go ./internal ./cmd
```

## 代码风格

- 标准 Go 风格，导出的标识符要有注释。
- 关键逻辑（阈值判断、跨平台兼容、quick 行为）请写清「为什么」，而不只是「做什么」。
- 跨平台代码用 `runtime.GOOS` 分支，并对缺失能力**降级 + 标注**，不要直接 panic。
- 保持默认探测频率保守（≥ 1s），禁止任何压测/泛洪能力。

## 特别欢迎的方向

- **新的平台快照采集器**（macOS 上的 Wi-Fi、Windows 的 WLAN、Android root 下的信息）。
- **新的检测规则**（例如：DHCP 续租、PMTUD 黑洞、IPv6 回退）。
- **报告模板改进**（更清晰的申诉文案、更多图表）。
- **翻译**（本文件、README、界面提示语）。

## 提交 PR

1. Fork 并新建分支：`git checkout -b feat/my-feature`
2. 小步提交，commit message 说明**动机**。
3. 发起 PR，描述里写清：改了什么、为什么、如何验证。

使用 [Bug 模板](.github/ISSUE_TEMPLATE/bug_report.md) 或
[Feature 模板](.github/ISSUE_TEMPLATE/feature_request.md) 开 Issue。

## 行为准则

请保持友善、就事论事。我们做这个工具，是为了帮被「网没问题」气到的人。

---

# Contributing (English)

Thanks for helping! Please:

1. `make test`, `make vet`, `gofmt -s -w .` before submitting.
2. Add tests for new logic; skip network tests under `testing.Short()`.
3. **Never** add telemetry, uploads or runtime dependencies — that is a hard red line.
4. Keep default probe rates conservative and never add flooding/attack features.
