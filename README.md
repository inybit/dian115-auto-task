# 癫影 m.dian115.com 每日自动任务（油猴脚本）

自动完成 [m.dian115.com](https://m.dian115.com) 的每日例行玩法：
**签到**、**幸运转盘**、**幸运大富翁**、**社区三色球**。

采用 **API 直调** 而非 DOM 点击——页面是 Vue SPA，规则简单稳定，不依赖脆弱的选择器。

## 特性

- ✅ 四个功能全部自动跑，按各自每日额度（`used_today < max_plays`）执行
- ✅ 复用浏览器当前登录态（纯 cookie 认证，`withCredentials`），**不处理密码、不存凭据**
- ✅ 右下角浮动日志面板，含"立即执行"与"收起"按钮
- ✅ 按自然日在 localStorage 去重，刷新/多标签不会重复执行
- ✅ 社区三色球默认**关闭**——它需要选号投注（博彩式烧积分），必须在配置里显式填号码才启用
- ✅ 余额安全阀：低于阈值停止消耗积分的动作

## 安装

1. 安装 [Tampermonkey](https://www.tampermonkey.net/)（油猴）
2. 打开本仓库 `dian115-auto.user.js`，点 `Raw` 即弹出安装
3. 先在 **m.dian115.com 登录一次**（普通浏览器登录即可，脚本会复用会话）
4. 刷新任意页面，右下角出现面板即运行

## 配置

脚本顶部 `CONFIG` 对象：

| 键 | 默认 | 说明 |
|---|---|---|
| `AUTO_RUN` | `true` | 加载页面是否自动执行（每日一次） |
| `SHOW_PANEL` | `true` | 显示右下角面板 |
| `SIGNIN_MODE` | `normal` | 签到模式：`normal`(稳健必得) / `lucky`(运气，可能大奖也可能倒霉/空签) |
| `SIGNIN_ENABLED` | `true` | 签到开关 |
| `WHEEL_ENABLED` | `true` | 幸运转盘开关 |
| `MONOPOLY_ENABLED` | `true` | 幸运大富翁开关 |
| `COMMUNITY_ENABLED` | `false` | 社区三色球开关（投注消耗积分，默认关） |
| `COMMUNITY_NUMBERS` | `[]` | 社区三色球选的 3 个号码，**必须恰好 3 个**（如 `[7, 21, 66]`） |
| `COMMUNITY_UNITS` | `1` | 每期投注注数 |
| `BALANCE_FLOOR` | `10` | 余额安全阀，低于此值停止耗分动作 |

> 想自动玩三色球：把 `COMMUNITY_ENABLED` 设为 `true` 并填 `COMMUNITY_NUMBERS = [a, b, c]`。
> 社区三色球是"开奖类"玩法，选号影响中奖，**请自行判断是否值得投注**。

## BrowserProof 防爬（v1.1.0）

站点对业务 API 做了自研的 **ECDSA 签名防爬**（axios 请求拦截器）。脚本 v1.0.0
用裸 `fetch` 直调被挡，服务端返回 `browser_proof_required`（"browser proof required"）。
脚本已内置完整客户端，逐字对齐逆向结果：

1. 每请求带 `X-Portal-Visitor-ID`（复用 `localStorage.portal_visitor_id`）+ `X-Portal-Current-Path`
2. `GET /auth/browser-challenge` → `{enabled, proof, ttl, expires_at}`（proof 缓存 ~30s）
3. 有 proof 则带 `X-Portal-Browser-Proof`
4. `POST /auth/browser-session` 注册 ECDSA P-256 公钥，返回 `server_time_ms` 做时钟对齐
5. 用私钥对
   `portal-browser-request/v1\n<METHOD>\n<path>\n<ts>\n<nonce>` 做 ECDSA-SHA256 签名 → base64url，
   挂 `X-Portal-Browser-TS` / `-Nonce` / `-Sig`
6. 遇 `code ∈ {browser_proof_required, browser_proof_invalid}` 自动重取 proof、重注册、重试一次

**关键约束：** 私钥非可导出（`extractable:false`），存站点自身
indexedDB `portal-browser-security-v1` / store `keys` / key `request-signing-p256`。
脚本**复用同一把站点私钥**签名，绝不自主另建新钥——否则会与服务端当前绑定的公钥冲突，
进而弄坏站内在用的请求。私钥缺失时才生成一把写回同一 store，与应用共享。

## 工作原理（逆向数组，便于自查）

以下并入审计信息（base = `/api/portal`，cookie 认证）：

| 功能 | Method & 路径 | Body | 返回 |
|---|---|---|---|
| 游戏状态 | GET `/games/status` | — | `{ items:{ daily_wheel, monopoly, community_lottery } }`，各项含 `{ used_today, max_plays, award_today, daily_cap, cost }` |
| 签到 | POST `/signin` | `{ mode: "normal"\|"lucky" }` | `{ award, lucky_tier, new_balance }` |
| 幸运转盘 | POST `/lottery/wheel` | — | `{ prize, new_balance }` |
| 幸运大富翁 | POST `/games/monopoly/play` | — | `{ tiles, award_points, steps, new_balance }` |
| 三色球状态 | GET `/games/community-lottery/status` | — | `{ participant_count, ticket_count, … }` |
| 三色球购买 | POST `/games/community-lottery/buy` | `{ numbers:[3], units }` | `{ new_balance }` |

签到 `normal` 模式必得积分；`lucky` 模式 `award` 可能为负（"倒霉签"）——默认 `normal` 以稳健。

## 开发 / 维护

- 改完把 `@version` 递增，`git tag` 打版
- 保持 `CONFIG` 在顶部集中管理，便于用户配置
- 新玩法上线：在 `api()` 加端点、在 `runAll()` 串起一个 `doXxx()`，并在 `README` 原理表补一行

## License

MIT