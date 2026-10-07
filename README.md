# cnki-cite — 知网搜索 + 批量导出引文格式

> CNKI (China National Knowledge Infrastructure) paper search & batch citation
> export (GB/T 7714 / EndNote / e-learning), pure Python, no browser needed.

复刻知网「搜索论文 → 点引用 → 复制引文格式」的完整流程，纯 Python 实现，
无浏览器依赖。支持 GB/T 7714、EndNote、知网研学三种格式。

## 安装

```bash
pip install requests beautifulsoup4 numpy pillow pycryptodome
```

## 用法

```bash
# 只列搜索结果（默认按主题字段）
python cnki_cite.py search 大语言模型

# 搜索并导出全部引文（GB/T 7714），写入 大语言模型-引文.txt
python cnki_cite.py cite 大语言模型

# 搜 2 页、只取前 5 条、附 EndNote+研学格式、另存结构化 JSON
python cnki_cite.py cite 大语言模型 --pages 2 --top 5 --format all --json out.json

# 按作者搜、按被引降序（--sort relevance|time|cited|download|overall）
python cnki_cite.py cite 知识图谱 --field AU --sort cited

# 已有导出加密 ID 时直接取引文
python cnki_cite.py ids <exportId1> <exportId2>
```

## 检索字段（16 种，`--field`）

| 代码 | 含义 | 代码 | 含义 |
|---|---|---|---|
| SU | 主题（默认） | RP | 通讯作者 |
| TKA | 篇关摘 | AF | 作者单位 |
| KY | 关键词 | FU | 基金 |
| TI | 篇名 | AB | 摘要 |
| FT | 全文 | CO | 小标题 |
| AU | 作者 | RF | 参考文献 |
| FI | 第一作者 | CLC | 分类号 |
| LY | 文献来源 | DOI | DOI |

字段代码与排序代码均从 kns8s 前端 DOM `data-val` / `data-sort` 实抓（2026-10-08）。

## 排序方式（`--sort`）

`relevance`(相关度=FFD) / `time`(发表时间=PT，默认) / `cited`(被引=CF) /
`download`(下载=DFR) / `overall`(综合=ZH)，均为降序。知网侧限制：排序只在
800 万条记录以内有效。默认（`time`）与知网原生行为一致：首页不传排序参数，
翻页用 `PT desc`。

退出码：0 成功；2 验证码未通过；3 无结果；1 其他错误。

## 工作原理（2026-10-07 实测逆向）

1. **搜索**：`POST https://kns.cnki.net/kns8s/brief/grid`，表单仿 kns8s 前端 SPA
   （`QueryJson` + `aside` + `searchFrom` 等）。第 1 页 `boolSearch=true`；
   翻页 `boolSearch=false` + `pageNum` + 第 1 页响应里的 `#hidTurnPage` 令牌 +
   `sortField=PT&sortType=desc` + QueryJson 填充 `Products` 与 `SearchFrom=4`。
2. **引文**：`POST https://kns.cnki.net/dm8/API/GetExport`，
   参数 `filename=<导出加密ID>&displaymode=GBTREFER,elearning,EndNote&uniplatform=NZKPT`。
   该 ID 就是搜索结果行里 `input.cbItem` 的 value，与详情页「引用」弹窗同源。
3. **WAF 过验**（内置，全自动）：知网对部分请求随机返回 `-403` 滑块挑战
   （AJ-Captcha blockPuzzle）或软封（200 + 空结果）。求解器流程：
   - `POST /verify-api/get` 拿底图 + 拼图块 + `token` + `secretKey`
   - FFT SSD 模板匹配定位缺口（块图全高 PNG，先按 alpha 包围盒裁剪）
   - `x = 310 × 缺口x / 底图宽`，AES-ECB-PKCS7 加密 `{"x":..,"y":5}` 作 `pointJson`
   - `POST /verify-api/web/check`；单次匹配不中自动换新图重试（≤6 次）
   - 成功后 `GET returnUrl?captchaId=...` 拿放行 cookie，重放原请求
4. **会话缓存**：验证过的 cookie 存在脚本旁 `_cnki_state.json`，下次运行直接复用，
   减少 WAF 触发；失效时自动重新过验。

输出说明：GB/T 7714 文本已去掉弹窗里的 HTML 标签和前导编号 `[n]`；
`--format all` 时 EndNote / 研学字段按原始多行排版。

## 已知边界

- 挑战类型若连续抽到 clickWord（点击字验证码），求解器会刷新重试直到抽到滑块；
  极端情况下连续 clickWord 会报退出码 2，稍后重跑即可。
- 导出接口逐条调用，默认间隔 0.35s；大批量（数百条）请分批，避免触发限流。
- 知网接口随时可能改版；失效时先重跑，再对照本文件第 2 节检查表单字段。

## 隐私与合规

- 运行产生的 `_cnki_state.json` 缓存知网会话 cookie，**只存在于本机**，
  已列入 `.gitignore`，请勿分享或提交给任何人。
- 本工具只读取文献元数据与引文格式（公开可浏览内容），不下载全文，
  不绕过任何付费权限。请遵守知网服务条款，仅用于个人学术用途。

## License

Copyright (C) 2026 66666-design

本项目以 **GNU Affero General Public License v3.0 (AGPL-3.0-or-later)** 发布。

这是刻意选择的强保护条款：任何人在修改本代码后对外分发、或将其部署为
网络服务（含 SaaS），都必须以同协议向使用者提供完整源代码。
详见 [LICENSE](LICENSE) 或 https://www.gnu.org/licenses/agpl-3.0.html 。
