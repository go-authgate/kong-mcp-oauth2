# kong-mcp-oauth2 — MCP 統一 OAuth 入口（Kong + Signet）

[![Docker Image](https://github.com/go-authgate/kong-mcp-oauth2/actions/workflows/docker.yml/badge.svg)](https://github.com/go-authgate/kong-mcp-oauth2/actions/workflows/docker.yml)
[![Trivy Security Scan](https://github.com/go-authgate/kong-mcp-oauth2/actions/workflows/security.yml/badge.svg)](https://github.com/go-authgate/kong-mcp-oauth2/actions/workflows/security.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/go-authgate/kong-mcp-oauth2)](https://goreportcard.com/report/github.com/go-authgate/kong-mcp-oauth2)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-authgate/kong-mcp-oauth2.svg)](https://pkg.go.dev/github.com/go-authgate/kong-mcp-oauth2)
[![Release](https://img.shields.io/github/v/release/go-authgate/kong-mcp-oauth2)](https://github.com/go-authgate/kong-mcp-oauth2/releases)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> English version: [README.md](README.md)
>
> 接真 Signet 的 macOS 實機操作手冊請見 [HANDS-ON.zh-TW.md](HANDS-ON.zh-TW.md)。
>
> 用 ngrok 把示範環境開上公網、給遠端 MCP client（MCP Inspector、claude.ai）連線：[NGROK.zh-TW.md](NGROK.zh-TW.md)。

`mcp-oauth2` 是一個 Kong [go-pdk](https://github.com/Kong/go-pdk) plugin（依
Kong 官方[Develop Go plugins](https://developer.konghq.com/custom-plugins/go/)
指南開發），在**所有 MCP server 前面架起單一的 OAuth 入口**。公司內部的 MCP 服務本來就掛在
[Kong](https://github.com/Kong/kong) 後面；這個 plugin 讓它們不再接受各自手填的
PAT，改成要求 [Signet](https://github.com/go-signet) 簽發的 OAuth access token——在本地用 **RS256 + JWKS**
驗證後，把可信身分（`X-MCP-*` header）往後面的 MCP server 送（預設不再轉發 bearer token）。

## 架構總覽

![kong-mcp 架構圖——完整的 MCP OAuth 握手流程](kong-authgate-mcp.svg)

上圖把整段握手從頭走到尾：**A · 探索（Discovery）**——Kong 告訴 client 流程在哪裡
（步驟 ② ③）；**B · OAuth**——client 自己對 Signet 跑 Auth Code + PKCE，同時 Kong
抓取 JWKS；**C · 驗證後放行（Verified access）**——Kong 在步驟 ⑤ 於本地離線驗證 RS256
token，再帶上 `X-MCP-Subject` / `X-MCP-Scope` 轉送到後端。可編輯原始檔：
[`architecture.excalidraw`](architecture.excalidraw)，到
[excalidraw.com](https://excalidraw.com) 開啟即可調整。下方兩張 Mermaid 圖是同一段
流程、可在 GitHub 直接渲染的輕量版。

```mermaid
graph LR
    client["MCP client<br/>（自己跑 PKCE）"]
    kong["Kong<br/>+ mcp-oauth2 plugin"]
    authgate["Signet<br/>授權伺服器"]
    mcp["MCP server(s)<br/>gitea / sentry"]

    client <-->|"MCP 請求<br/>+ 401 挑戰 / PRM"| kong
    kong -->|"放行 + X-MCP-Subject / X-MCP-Scope"| mcp
    client -->|"Auth Code + PKCE<br/>/authorize · /token"| authgate
    kong -.->|"抓 JWKS<br/>（快取、自動輪替）"| authgate
```

**Kong 不跑 OAuth 流程。** 它只負責*告訴 client 流程在哪裡*（步驟 ②③），以及
**驗證跑完流程後拿回來的 token**（步驟 ⑤）。MCP client 自己對 Signet 跑 Auth Code + PKCE。
一套 plugin 設定就能同時罩住所有 MCP server——對每個 service 掛上去、各自填不同的
`resource_path` 即可。

## 認證握手流程

這是 MCP 的授權握手（2025-06 MCP spec，建構在 RFC 9728 Protected Resource
Metadata 與 RFC 6750 bearer token 之上）。編號對應 `main.go` 裡的註解：

```mermaid
sequenceDiagram
    participant C as MCP client
    participant K as Kong + mcp-oauth2
    participant A as Signet
    participant M as MCP server

    C->>K: GET /mcp/server（未帶 token）
    K-->>C: ② 401 + WWW-Authenticate：<br/>Bearer resource_metadata="‹PRM URL›"
    C->>K: GET /.well-known/oauth-protected-resource/mcp/server
    K-->>C: ③ 200 Protected Resource Metadata<br/>（authorization_servers、scopes）
    C->>A: Auth Code + PKCE（/authorize、/token）
    A-->>C: RS256 access token
    K-)A: 抓 JWKS（快取／自動輪替）
    C->>K: GET /mcp/server + Bearer ‹jwt›
    Note over K: ⑤ 驗 簽章(JWKS) + exp（iss 除非 skip_issuer_check）<br/>+ type=access（除非 skip_type_check）+ scope<br/>+ aud（除非 skip_audience_check）
    K->>M: 放行 + X-MCP-Subject / X-MCP-Scope
    M-->>K: 200
    K-->>C: 200
```

| 步驟 | 由誰            | 發生什麼事                                                                                                                                                                                                                 |
| ---- | --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ②    | Kong → client   | 沒帶 / 帶錯 token 的請求 → `401` + `WWW-Authenticate: Bearer resource_metadata="<PRM URL>"`                                                                                                                                |
| ③    | Kong → client   | client 去抓 `<PRM URL>` → plugin 回傳 Protected Resource Metadata（要用哪個 Signet、要哪些 scope）                                                                                                                         |
| —    | client ↔ Signet | client 從 metadata 找到 Signet，自己跑 **Auth Code + PKCE** 換 access token                                                                                                                                                |
| ⑤    | Kong            | client 帶 `Authorization: Bearer <jwt>` 重試 → plugin 驗 **簽章(JWKS) + exp**（**iss** 除非 `skip_issuer_check`）（**`type=access`** 除非 `skip_type_check`）**+ scope**（**aud** 除非 `skip_audience_check`）→ 放行往後送 |

## 為什麼選 RS256 + JWKS（不是 HS256）

- **gateway 上不放共享密鑰。** 用 HS256 的話，gateway 得持有 Signet 的簽章密鑰
  ——等於把一把「能偽造任何 token」的鑰匙擺在最外緣。RS256 + JWKS 之下，Kong 永遠
  只摸得到**公鑰**。
- **金鑰輪替零接觸。** 在 Signet 的 JWKS 換金鑰，Kong 會自動接手（keyfunc 背景
  輪替），不用改 Kong 設定。
- **擋掉 alg-confusion。** plugin 把接受的演算法鎖死在
  `RS256/RS384/RS512`、拒絕 `HS*`。這擋掉了最經典的偽造手法：攻擊者拿 RSA **公鑰**
  當 HMAC 金鑰去簽 HS256。（驗證矩陣第 5 列最後一項就是專門測這個。）

驗證引擎是 [`MicahParks/keyfunc`](https://github.com/MicahParks/keyfunc)，它把
JWKS 的抓取、記憶體快取、背景輪替、未知 `kid` 的限流補抓全包好了——這些正是用 Lua
自己刻最容易出錯的部分。

## 設定參數

每個 MCP 資源對應一個 plugin 實例。完整範例見 `kong.yml`。

| 參數                     | 必填 | 說明                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ------------------------ | ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `issuer`                 | ✅   | Signet base URL，必須與 token 的 `iss` claim 逐字元相符（除非設了 `skip_issuer_check`）。                                                                                                                                                                                                                                                                                                                                                                                                                |
| `gateway_origin`         | ✅   | 對外可達的 Kong origin，例如 `https://gw.example.com`，用來組出 PRM URL。                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `resource_path`          | ✅   | 此資源的路徑，例如 `/mcp/server`。                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `jwks_uri`               |      | Signet JWKS endpoint（RS256）。接受的演算法固定鎖在 RS 家族。留空則改由 issuer 的 AS metadata **自動發現**（RFC 8414 `/.well-known/oauth-authorization-server`，失敗時退回 OIDC discovery；快取 1 小時，metadata 的 `issuer` 必須與設定值相符）。當 Kong 連 Signet 的位址與 client 不同時（例如 compose 範例裡的 `host.docker.internal`）才需要手動指定。                                                                                                                                                |
| `required_scopes`        |      | token 的 `scope` 必須包含全部所列項目，否則 `403 insufficient_scope`。                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `audience`               |      | **只影響 token 的 `aud` 驗證**，預設為 `gateway_origin + resource_path`。PRM 的 `resource` 永遠維持 canonical URL（RFC 9728 §3.3），只有在 Signet 發固定的非 URL `aud` 時才需要設。                                                                                                                                                                                                                                                                                                                      |
| `leeway_seconds`         |      | `exp`/`nbf` 的時鐘偏移容忍秒數，建議 `60`。必須 ≥ 0。                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `upstream_auth_mode`     |      | 後端收到什麼來取代 client 的 bearer token。**預設 `strip`**：驗證完後移除 `Authorization` header——身分只經由可信的 `X-MCP-*` header 傳遞，後端不再持有一顆可重放的活憑證。`passthrough` 原樣轉發 client token（0.6 之前的行為；僅在後端自己驗 token 時使用，例如 Gitea demo route）。`static` 移除 client token、改送一組固定的上游憑證。                                                                                                                                                                |
| `upstream_auth_token`    |      | `upstream_auth_mode: static` 時必填（缺了會讓每個請求都回 `500 server_error` + critical log——絕不靜默退回其他模式）。要送給上游的憑證。用 Kong 的 `${{ env "KONG_UPSTREAM_TOKEN" }}` 替換語法避免把秘密 commit 進宣告式設定檔。                                                                                                                                                                                                                                                                          |
| `upstream_auth_header`   |      | 僅 `static` 模式。攜帶上游憑證的 header；預設 `Authorization`，值會加上 `Bearer ` 前綴。自訂名稱（例如 `X-Api-Key`）則原樣送出、不加前綴——且 client 的 `Authorization` header **仍會被移除**。                                                                                                                                                                                                                                                                                                           |
| `upstream_extra_headers` |      | `"Name: value"` 字串清單，**所有**模式都會設在每個上游請求上（多租戶／來源標記）。只切第一個冒號，值可以含冒號（URL）。保留名稱在驗證時直接拒絕：`Authorization`、任何 `X-MCP-*`、以及使用中的 `upstream_auth_header`。                                                                                                                                                                                                                                                                                  |
| `skip_issuer_check`      |      | ⚠️ 預設 `false`。設 `true` 時**不**拿 token 的 `iss` claim 跟 `issuer` 比對。`issuer` 欄位仍為必填（用於 AS metadata 發現與 PRM 回應）。僅在已知 token 簽發者不帶 `iss` claim 時使用。                                                                                                                                                                                                                                                                                                                   |
| `skip_type_check`        |      | ⚠️ 預設 `false`。設 `true` 時略過 `type=access` 檢查——refresh token 與沒有 `type` claim 的 token 都會被當成 bearer 憑證接受。僅在已知授權伺服器不發 `type` claim 時使用。                                                                                                                                                                                                                                                                                                                                |
| `skip_control_chars`     |      | ⚠️ 預設 `false`。設 `true` 時停用對轉發 claims（`X-MCP-*` headers）的 CR/LF 注入防護。僅在以非標準 token 除錯時暫時使用。`upstream_auth_*` 的**設定值**一律無條件驗證——這個開關永遠不影響它們（設定值裡的控制字元只會是打錯字或注入,不存在合理的除錯情境）。                                                                                                                                                                                                                                             |
| `skip_audience_check`    |      | ⚠️ 預設 `false`：`aud` **預設即強制驗證**（RFC 8707 / MCP 規範——資源伺服器 MUST 驗證 token 是簽發給自己的）。Signet 發出 per-resource `aud`：client 在 token 請求帶 `resource=<gateway_origin + resource_path>`，且該 URL 必須在 client 的 `allowed_resources` 白名單內。比對值是逐字元、區分 scheme／斜線的精確比對——沒綁定相符 `aud`（或完全沒有 `aud`）的 token 一律 `401`。僅在 token 簽發者無法發 per-resource `aud`（例如 Gitea demo route）或暫時除錯 token 簽發時才設 `true`（見下方重放警告）。 |
| `debug_claims`           |      | ⚠️ 預設 `false`。設 `true` 時，對每個 plugin 解碼的請求把完整解碼後的 claim set 傾印到 Kong 的 debug log——方便維運人員找出非預期 `401`/`403` 背後是哪個 claim 帶著 scope／`aud`／`type`。由 config 控管，而**非**僅靠 log level（`kong.Log.Debug` 不分 `log_level` 每次呼叫都會送到 Kong），所以未主動開啟前一律關閉。需搭配 `KONG_LOG_LEVEL=debug` 才看得到輸出。claims 可能含 PII，請審慎且短暫開啟。                                                                                                  |

只接受 `type=access` 的 token；Signet 的 refresh token（金鑰、`iss`、`aud`、
`scope` 都相同，只有 `type` 與較長的 `exp` 不同）會被回 `401 invalid_token` 拒絕。

> go-pdk 產生的 schema 無法標記必填欄位，所以三個必填欄位改在第一個請求時驗證——
> 缺欄位時所有請求都會回 `500 server_error` 並寫一行 critical log，而不是默默地
> 行為異常。
>
> **路由陷阱。** 每條 Kong route 必須**同時**匹配 `resource_path` 與其 PRM 路徑
> （`/.well-known/oauth-protected-resource` + `resource_path`）。否則 client 在步驟 ③ 來抓 metadata 時
> Kong 沒有對應 route 可交給 plugin，plugin 就不會回傳 metadata。請看 `kong.yml`
> 裡每條 route 的 `paths:` 清單。
>
> **跨資源重放警告（若你設了 `skip_audience_check: true`）。** 略過檢查時不會驗
> `aud`，所以區分不同 MCP 資源的只剩 `scope`。一顆帶多個 scope 的 token
> （例如 `mcp:gitea mcp:sentry`）會在**每個**它帶有對應 scope 的資源上都被接受；
> 又因為原始 bearer 會原封不動往後送，收到它的後端可以拿去重放到另一個資源。
> 這正是此檢查預設開啟的原因；若為了除錯 token 簽發而暫時略過，把資源視為彼此
> 隔離之前務必把開關拿掉。
>
> **從 ≤ 0.4.x 遷移（`require_audience` 已移除）。** `aud` 驗證現在是預設行為，
> 舊的 opt-in 欄位已刪除：declarative config 裡若還留著 `require_audience`，
> **Kong 載入時會被 schema 驗證直接拒絕**（刻意的大聲失敗，不做靜默的行為改變）。
>
> - `require_audience: true` → 刪掉該行（新預設已涵蓋）。
> - `require_audience: false` → 改成 `skip_audience_check: true`——但請先確認
>   token 是否其實可以用正確的 `aud` 簽發（RFC 8707 `resource` 參數，見下方
>   動手前確認）。
>
> 升級後若沒綁相符 `aud` 的 token 開始收到 `401`，Kong log 的 `rejected token`
> 行會寫明 audience 不符；`skip_audience_check: true` 是暫時的逃生口。
>
> **從 ≤ 0.5.x 遷移（`Authorization` 預設不再轉發）。** client 的 bearer token
> 現在會在請求送達後端之前被**移除**（`upstream_auth_mode` 預設 `strip`）——
> 與上面 `require_audience` 的遷移同一套判準：寧可大聲的 breaking change,
> 不做靜默的不安全預設。若你的後端自己驗證轉發過來的 token,一行還原舊行為:
>
> ```yaml
> upstream_auth_mode: "passthrough"
> ```
>
> 安全的升級順序:先讓後端改信 `X-MCP-*` 身分 header(並限制它只接受來自
> Kong 的流量——見維運注意事項),再拿掉 `passthrough` 這一行。

## 1. 編譯 plugin

go-pdk plugin 是會講 pluginserver RPC 協定的一般執行檔——不用 cgo、也不是 `.so`。
完整 `go build` 需要網路（go-pdk 的 protobuf 相依），請在 repo 根目錄跑：

```bash
go mod tidy && go build -o mcp-oauth2 .
```

## 2. 接進 Kong

註冊 plugin，並把 pluginserver 指向 binary（環境變數，見 `docker-compose.yml`）：

```bash
KONG_PLUGINS=bundled,mcp-oauth2
KONG_PLUGINSERVER_NAMES=mcp-oauth2
KONG_PLUGINSERVER_MCP_OAUTH2_START_CMD=/usr/local/bin/mcp-oauth2
KONG_PLUGINSERVER_MCP_OAUTH2_QUERY_CMD=/usr/local/bin/mcp-oauth2 -dump
```

## 3. 啟動示範環境

```bash
docker compose up --build
```

這會啟動 DB-less 的 Kong（proxy 在 `:8000`；未認證的 admin API 綁在 container 的
loopback、不對外發布——見 `docker-compose.yml`）加兩個假的 MCP upstream。在期待
token 能通過驗證之前，請先改 `kong.yml` 讓 `issuer` / `gateway_origin` /
`jwks_uri` 指向你們真正的 Signet。

## 4. 驗證矩陣

`docker compose up` 後實際跑一遍握手。示範環境把 `$GW` 換成
`http://localhost:8000`（或你的 `gateway_origin`）。

> 第 1–2 列用內建的 stub demo 就能跑。第 3–5b 列需要真的 token：先把 `kong.yml`
> 的 `issuer` / `jwks_uri` 指向 Signet（用預設的 placeholder 設定會回
> `503 temporarily_unavailable`，因為 `auth.example.com` 抓不到 JWKS）。`aud`
> 預設即強制檢查，所以第 3–5a 列的 token 必須綁定資源——取 token 時帶
> `resource=<gateway_origin + resource_path>`（RFC 8707）。第 5c 列是
> 例外——HS256 偽造會在抓 JWKS **之前** 就先被擋（演算法先被鎖定），回
> `401 invalid_token`，所以即使用 placeholder 設定也是 `401`。

| #   | 測試項目                   | 指令                                                                                     | 預期結果                                                          |
| --- | -------------------------- | ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| 1   | 未認證 → 挑戰              | `curl -i $GW/mcp/server`                                                                 | `401` + `WWW-Authenticate: Bearer resource_metadata="…"`          |
| 2   | 回傳 PRM 文件              | `curl -s $GW/.well-known/oauth-protected-resource/mcp/server`                            | JSON 含 `resource`、`authorization_servers`、`scopes_supported`   |
| 3   | 有效 token → 放行          | `curl -i $GW/mcp/server -H "Authorization: Bearer $GOOD"`                                | MCP upstream 回 `200`                                             |
| 4   | 過期 token                 | `curl -i $GW/mcp/server -H "Authorization: Bearer $EXPIRED"`                             | `401 invalid_token`                                               |
| 5a  | 缺少 scope                 | 沒有 `required_scopes` 的 token → `curl -i $GW/mcp/server -H "Authorization: Bearer $X"` | `403 insufficient_scope`                                          |
| 5b  | **跨 audience**            | 為另一個資源簽發的 token（aud 預設即強制驗證）                                           | `401 invalid_token`（aud 不符）                                   |
| 5c  | **HS256 偽造（金鑰位元）** | 拿 RSA 公鑰當 HMAC 金鑰偽造一顆 HS256 token                                              | `401 invalid_token` — **必須被擋**（alg confusion）               |
| 6a  | **token 不外流到上游**     | 有效 token、預設 `strip` 模式 → 呼叫 demo 的 `whoami` 工具                               | `token_forwarded: false`——沒有 `Authorization` 到達後端           |
| 6b  | **`X-MCP-*` 偽造**         | 有效 token（sub=alice）+ client 自帶 `X-MCP-Subject: admin` 與 `X-MCP-Foo: x`            | 後端看到 `subject: alice`（單一值、來自 token）且沒有 `X-MCP-Foo` |

第 **5b**、**5c** 與 **6b** 列是安全關鍵——上線前務必跑過。第 6b 列用與 6a
相同的 `whoami` 呼叫:在 client 端注入偽造 header,確認 echo 回來的身分來自
token、不是 client 自填的值。

## Signet 端動手前確認

要端到端跑通之前，先在 Signet 確認三件事（解一顆實際的 **access token**，不是只看
`id_token`）：

1. **JWKS 取得出 keys。** `GET <issuer>/.well-known/openid-configuration` →
   其 `jwks_uri` 回傳非空的 `keys` 陣列。
2. **access token 是 RS256 簽。** 解一顆實際的 access token，header 的 `alg` 是
   `RS256`（不是 `HS256`），且 `kid` 對得到 JWKS 裡某把 key。Signet 預設常是
   `JWT_SECRET`（HS256）——請確認你們真的已經把 **access token**（不只 `id_token`）
   切到非對稱簽。
3. **iss 一致。** token 的 `iss` 與 plugin 設定的 `issuer` 逐字元相符（注意結尾斜線）。
4. **`aud` 綁定資源。** `aud` 預設即強制檢查，所以每顆 token 都要用 RFC 8707
   resource binding 取得：先在 Signet 把 `<gateway_origin + resource_path>`
   （例如 `https://gw.example.com/mcp/server`）加進該 OAuth client 的
   `allowed_resources`（空白名單 = 全拒，token endpoint 會回 `invalid_target`），
   再於 token 請求帶 `resource=<該 URL>`。解碼 token 確認 `aud` 與 plugin 的
   預期值完全一致。

## 維運注意事項

- **自動發現會把 metadata endpoint 也納入可用性鏈。** `jwks_uri` 留空時，第一顆
  token（以及每小時一次的更新）還會多依賴 issuer 的 AS metadata endpoint；冷快取
  下發現失敗回 `503`、下一個請求重試，而每小時更新失敗則沿用上次發現的
  `jwks_uri`，不影響線上流量。
- **JWKS endpoint 要高可用。** **初次**抓取失敗時，帶 token 的請求會回
  `503 temporarily_unavailable`（不是 `401`，client 不會誤以為要重跑 OAuth），
  下一個請求會重試——初次抓失敗的結果不會被快取。抓取等待上限 10 秒，且在 per-URI
  鎖下進行，慢的 Signet 不會卡住其他資源的流量。注意：key 一旦進了快取，帶未知
  `kid` 的 token 會回 `401 invalid_token`（離線驗證分不出「輪替期間剛換上的 key」與
  「偽造的 kid」），而且每小時的更新若抓到含一把壞 key 的 JWKS，可能把已快取的 key
  清掉直到下一次乾淨的更新。輪替時請保持 JWKS 有效，並讓新舊 key 充分並存。
- **瀏覽器端的 MCP client 需要 CORS。** CORS preflight（`OPTIONS`、不帶
  `Authorization`）會被回 `401` 挑戰；若有 web client 要直連 gateway，請在
  route 上掛 Kong 的 `cors` plugin。
- **輪替時讓新舊 key 並存。** 讓舊 key 與新 key 在 JWKS 並存一段 overlap 時間，
  在途 token 才不會被誤殺。
- **access token TTL 設短。** 跟所有離線驗證一樣，被撤銷的 token 會一直有效到它的
  `exp`——以分鐘計、不要以小時計。
- **bearer token 預設不會送到後端。** 驗證完後,Kong 設定可信的 `X-MCP-*` 身分
  header（`Subject` / `Scope` / `Issuer` / `Audience` / `Client` / `Token-Id`
  / `Expires`）、清掉 client 自帶的其他任何 `X-MCP-*` 名稱,並在預設的
  `upstream_auth_mode: strip` 下移除 `Authorization` header——後端從此不再持有
  一顆可重放的活憑證。生效的模式會在 `info` level 記一行 log
  （`upstream auth mode: …`）。兩個推論:
  - **`passthrough` 會恢復舊的暴露面。** 設了它,每個 MCP 後端都會拿到一顆對
    **同一個**資源可重放到 `exp` 為止的活 token;請維持預設的 `aud` 驗證
    （不要設 `skip_audience_check`）,至少讓它跨不到 sibling 資源。
  - **`strip`/`static` 模式下,`X-MCP-*` 是後端唯一的身分來源——所以後端
    MUST 只接受來自 Kong 的流量**（network policy / mTLS / 私有網路）。任何
    繞過 gateway 的路徑都等於讓呼叫者自填 `X-MCP-Subject`。這本來就是部署
    契約;少了 token 當第二道防線後,它現在是承重牆。
