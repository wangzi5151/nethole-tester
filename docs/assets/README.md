# 截图与素材 / Screenshots & Assets

本目录的截图由工具**真实输出**生成：

| 文件 | 来源 | 说明 |
|---|---|---|
| `tui.svg` | `internal/ui` 白盒渲染 `View()` | 实时面板：三链路 sparkline + 网洞事件 |
| `report-html.svg` | 真实 `samples.jsonl` 数据 | 离线 HTML 报告的布局与真实延迟曲线 |
| `complaint.svg` | 真实 `complaint.txt` | 运营商申诉报告排版 |

> 使用 SVG 而非 PNG：仓库/浏览器按**访问者本机字体**渲染，中文在所有环境都正常显示，
> 而服务器端 PNG 渲染需要 CJK 字体，容易变方块。GitHub 直接支持 SVG 图片。

## 自己重新生成 / Regenerate

```bash
# 1. 抓一帧真实 TUI 文本
go test ./internal/ui/ -run TestRenderCapture -v

# 2. 用真实 samples.jsonl / complaint.txt 渲染 SVG（见项目 Issue/PR 中的脚本）
```

## 可选：录制 GIF 演示 / Optional demo GIF

```bash
# 用 asciinema 录制终端，再转 GIF
pkg install asciinema agg      # Termux
asciinema rec demo.cast
agg demo.cast docs/assets/demo.gif
```

## LOGO 概念 / Logo concept

「网络信号 + 黑洞」：三条水平信号线，其中一条中间断开成圆形空洞，象征
「看似连接、中间却有看不见的断裂」。主色 `#3ddc84`（信号绿）+ `#0f1115`（深空黑）。
ASCII 版见 `docs/logo.txt`。
