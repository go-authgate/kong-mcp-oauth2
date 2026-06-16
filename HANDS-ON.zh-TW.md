# kong-mcp-oauth2 安裝與驗證手冊（接真 AuthGate · macOS 實機操作版）

這份手冊帶你在 **macOS** 上，把 `mcp-oauth2` plugin 跑起來，並接上一個**真正的
AuthGate**（授權伺服器）完整走完 MCP OAuth 握手，逐列驗證安全性質。

> 本手冊只依賴此 repo 自身的檔案與一個你自己架的 AuthGate，**不需要**任何其他
> 範例專案。每個指令都在 Apple Silicon（M1 Max / arm64）+ colima + Docker 24
> 上實機跑過。Intel Mac 請把 `GOARCH=arm64` 改成 `GOARCH=amd64`。

產品說明、設定欄位、設計理由請看 [README.md](README.md) / [README.zh-TW.md](README.zh-TW.md)。
這裡只談「怎麼一步步跑起來並驗證」。

---

## 0. 前置需求

| 工具                    | 確認指令                                                         | 備註                                                           |
| ----------------------- | ---------------------------------------------------------------- | -------------------------------------------------------------- |
| Go 1.25.10+             | `go version`                                                     | 編譯 plugin（`go.mod` 的 `go` 指令為 1.25.10）                 |
| Docker                  | `docker version`                                                 | Docker Desktop、colima、OrbStack 皆可                          |
| Docker Compose          | `docker compose version` 或 `docker-compose version`             | v2 即可。本機若只有獨立版 `docker-compose`，下面指令照用即可   |
| curl / openssl          | 內建                                                             | 驗證用                                                         |
| jq / python3            | 內建 / `brew install jq`                                         | 解析 token endpoint 回傳的 JSON、解碼 JWT claims               |
| **一個跑著的 AuthGate** | `curl -s http://localhost:8080/.well-known/openid-configuration` | 本手冊假設 AuthGate 跑在 macOS host 的 `http://localhost:8080` |

> **colima 使用者**：先確認 daemon 起來了（`colima status`，沒有就 `colima start`）。
> 本手冊用到的 `host.docker.internal`（容器連回 macOS host）在 colima / 一般
> dockerd 上預設沒有，靠 [`docker-compose.authgate.yml`](docker-compose.authgate.yml)
> 裡的 `extra_hosts: host.docker.internal:host-gateway` 補上——已經幫你寫好，不用改。

---

## 1. 為什麼用「本機交叉編譯 + 掛載 binary」

倉庫附的 [`docker-compose.yml`](docker-compose.yml) 走 [`Dockerfile`](Dockerfile)，
**在 Docker 內** `go mod download` 再編譯 plugin。這在一般網路沒問題，但若你在
**有 TLS 攔截 proxy 的公司網路**（例如憑證被替換），Docker build 會卡在：

```text
go: github.com/Kong/go-pdk@v0.11.0: ... tls: failed to verify certificate:
x509: certificate signed by unknown authority
```

因為 BuildKit 容器內不帶你 macOS 的企業根憑證。為了繞過這點、也讓驗證更快，本
手冊改用 **本機交叉編譯 + 把 binary 掛進現成 `kong:3.9` image** 的方式，對應檔案：

- [`docker-compose.authgate.yml`](docker-compose.authgate.yml)：掛載本機編好的
  binary，並補上 `host.docker.internal` 與真 AuthGate 設定。
- [`kong.authgate.yml`](kong.authgate.yml)：把 plugin 指向你本機的 AuthGate
  （正式部署設定請看 [`kong.yml`](kong.yml) 的 placeholder）。

> 公司網路沒有攔截 proxy 的話，你也可以直接 `docker compose up --build` 走原始
> 流程（[`docker-compose.yml`](docker-compose.yml)），跳過第 2 步的交叉編譯。

---

## 2. 編譯 plugin

go-pdk plugin 是一支普通的執行檔（講 pluginserver RPC，無 cgo、無 `.so`）。

**本機自用 / 手動 smoke test：**

```bash
go mod tidy
go build -o mcp-oauth2 .
./mcp-oauth2 -dump | head        # 應印出 plugin schema（JSON）
```

**給 Linux 容器掛載用（本手冊主線）——交叉編譯：**

```bash
# Apple Silicon：
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o mcp-oauth2-linux .
# Intel Mac：把 arm64 換成 amd64
file mcp-oauth2-linux   # 應顯示 ELF 64-bit ... ARM aarch64（或 x86-64）
```

> `GOARCH` 要對齊 **Docker VM 的架構**，不是你 shell 的架構。Apple Silicon 上的
> colima / Docker Desktop 預設跑 arm64 VM，所以用 `arm64`。

---

## 3. 先從 AuthGate 的 discovery 抓真實值

**別用猜的**——`issuer` / `jwks_uri` 一律以 discovery 文件為準：

```bash
curl -s http://localhost:8080/.well-known/openid-configuration \
  | python3 -m json.tool | grep -iE '"issuer"|jwks_uri|token_endpoint|scopes_supported'
```

範例輸出（你的可能不同，以實際為準）：

```text
"issuer": "http://localhost:8080",
"jwks_uri": "http://localhost:8080/.well-known/jwks.json",
"token_endpoint": "http://localhost:8080/oauth/token",
"scopes_supported": ["openid", "profile", "email"],
```

---

## 4. 唯一的雷：`localhost` vs `host.docker.internal`

換成 `http://localhost:8080`（純 HTTP）少了自簽 TLS 與 `.local` DNS 兩個麻煩，但
**還剩一個**：Kong 在容器裡，容器的 `localhost` 是它自己，不是 macOS host。所以：

| 欄位             | 值                                                       | 為什麼                                                          |
| ---------------- | -------------------------------------------------------- | --------------------------------------------------------------- |
| `issuer`         | `http://localhost:8080`                                  | 拿來跟 token 的 `iss` **逐字元比對**（plugin 不連它，只比字串） |
| `jwks_uri`       | `http://host.docker.internal:8080/.well-known/jwks.json` | 由 **Kong 容器**去抓，要填容器連得到 host 的位址                |
| `gateway_origin` | `http://localhost:8000`                                  | 不變（這是 Kong proxy，給 host 端 client / 組 PRM URL 用）      |

[`kong.authgate.yml`](kong.authgate.yml) 已經照這樣寫好；
[`docker-compose.authgate.yml`](docker-compose.authgate.yml) 也已含
`extra_hosts: host.docker.internal:host-gateway`，**都不用改**。把第 3 步
discovery 抓到的 `issuer` / `jwks_uri` 主機名對齊你的環境即可。

---

## 5. ⚠️ scope：AuthGate 沒發的 scope 一定 403

上面 `scopes_supported` 只有 `openid profile email`，**沒有 `mcp:gitea`**。若 plugin
設 `required_scopes: [mcp:gitea]`，再有效的 token 也會 `403 insufficient_scope`。
`kong.authgate.yml` 已避開這點：gitea 路由 `required_scopes: []`（不檢查），sentry
路由用 `email`（AuthGate 真的會發）示範強制。要照產品語意用 `mcp:gitea`，得先去
AuthGate 端註冊並發給該 client。

---

## 6. ⚠️ aud：先把資源註冊進 client 的 `allowed_resources`

`kong.authgate.yml` 兩條路由都開了 `require_audience: true`（出廠值），token 的
`aud` 必須等於 `gateway_origin + resource_path`。AuthGate 用 **RFC 8707 resource
binding** 發 per-resource `aud`：取 token 時帶 `resource=<該 URL>`，AuthGate 就把
它寫進 `aud`。但有個前提——

> AuthGate 對 `resource` 參數有 **per-client 白名單**（`allowed_resources`，
> **空白名單 = 全拒**）。沒先註冊就帶 `resource` 取 token，會拿到
> `400 invalid_target`（"Requested resource is not allowed for this client"）。

到 AuthGate 的 client 設定（dashboard 的 **Allowed Resources** 欄位，多筆用逗號
分隔），把兩個資源 URL 加進去：

```text
http://localhost:8000/mcp/gitea, http://localhost:8000/mcp/sentry
```

> 除錯期間若想先排除 aud 因素，可把 `kong.authgate.yml` 的 `require_audience`
> 暫時改回 `false`（改完要 `--force-recreate kong`）——**驗完記得改回來**，
> 否則 token 可跨資源重放（見 README 的重放警告）。

---

## 7. 啟動 Kong demo stack（接 AuthGate）

用 AuthGate 版 compose 啟動（DB-less Kong + 兩個 stub MCP upstream）：

```bash
docker-compose -f docker-compose.authgate.yml up -d
# 若你的 Docker 有 compose v2 子指令，等價於：
#   docker compose -f docker-compose.authgate.yml up -d
```

確認三個容器都 Up：

```bash
docker-compose -f docker-compose.authgate.yml ps
```

- proxy（MCP 流量入口）：`http://localhost:8000`
- admin API：**只綁容器內 loopback、不對外發布**（未認證、可整份換掉設定）。需要
  除錯時用 `docker exec <kong 容器> curl http://127.0.0.1:8001/...`。

看 plugin 有沒有正常掛載：

```bash
docker-compose -f docker-compose.authgate.yml logs kong | grep -i pluginserver
# 應看到 "loading protocol ProtoBuf:1 for plugin mcp-oauth2"
```

---

## 8. 不用帳密就能驗「JWKS 連線通不通」

接真 AuthGate 最常見的失敗是 `jwks_uri` 容器連不到 → 所有 token 變 `503`。有個小
技巧能**不用任何憑證**就分辨「連線問題」還是「token 問題」：手刻一顆**演算法是
RS256（會通過 alg 鎖定）、但簽章是垃圾**的 token 丟進去——plugin 會去抓 JWKS、
找不到對應 `kid`，藉此反映「JWKS 抓得到 / 抓不到」：

```bash
GW=http://localhost:8000
header=$(printf '{"alg":"RS256","typ":"JWT","kid":"probe"}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')
payload=$(printf '{"iss":"http://localhost:8080","exp":9999999999,"type":"access","sub":"probe"}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')
PROBE="$header.$payload.AAAA"   # 故意給垃圾簽章
curl -si $GW/mcp/gitea -H "Authorization: Bearer $PROBE" | sed -n '1p;$p'
```

- 回 **`401 invalid_token`** → plugin 成功抓到 AuthGate 的 JWKS（只是 kid 對不上 /
  簽章驗不過）→ **連線 OK** ✅
- 回 **`503 temporarily_unavailable`** → JWKS 抓不到 → 檢查 `jwks_uri` 是不是用了
  `host.docker.internal`、AuthGate 有沒有在跑。

---

## 9. 驗證矩陣（逐列實測）

設一個方便的變數：

```bash
GW=http://localhost:8000
```

### Row 1 — 沒帶 token → 401 挑戰

```bash
curl -si $GW/mcp/gitea | sed -n '1p;/WWW-Authenticate/p'
```

預期：

```text
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="http://localhost:8000/.well-known/oauth-protected-resource/mcp/gitea"
```

### Row 2 — PRM 文件（Protected Resource Metadata, RFC 9728）

```bash
curl -s $GW/.well-known/oauth-protected-resource/mcp/gitea
```

預期（含 `resource`、`authorization_servers`，gitea 路由 `required_scopes: []`
所以不含 `scopes_supported`）：

```json
{
  "authorization_servers": ["http://localhost:8080"],
  "bearer_methods_supported": ["header"],
  "resource": "http://localhost:8000/mcp/gitea"
}
```

### Row 3 — 有效 token → 轉發到 upstream（200）

token 來源走 OAuth。下面用 `client_credentials` 直接打 token endpoint（端點以第 3
步 discovery 的 `token_endpoint` 為準），**一個資源換一顆 token**——`resource` 必須
已在 client 的 `allowed_resources`（見第 6 步）：

```bash
TOKEN_URL=http://localhost:8080/oauth/token

# 綁定 gitea 的 token
GOOD=$(curl -s -X POST "$TOKEN_URL" \
  -d grant_type=client_credentials \
  -d client_id=<id> -d client_secret=<secret> \
  -d 'scope=email' \
  -d 'resource=http://localhost:8000/mcp/gitea' | jq -r .access_token)

curl -si $GW/mcp/gitea -H "Authorization: Bearer $GOOD" | sed -n '1p;$p'
```

預期：

```text
HTTP/1.1 200 OK
hello from mcp-gitea
```

> 想先解碼確認 claims（`aud`、`iss`、`type=access`、header `alg=RS256`）：
>
> ```bash
> echo "$GOOD" | cut -d. -f2 | python3 -c "import sys,base64,json; s=sys.stdin.read().strip(); print(json.dumps(json.loads(base64.urlsafe_b64decode(s+'='*(-len(s)%4))), indent=2, ensure_ascii=False))"
> ```

### Row 5a — 缺少必要 scope → 403

sentry 路由要求 `email` scope。取一顆**綁定 sentry 但 scope 不含 email** 的 token：

```bash
NOSCOPE=$(curl -s -X POST "$TOKEN_URL" \
  -d grant_type=client_credentials \
  -d client_id=<id> -d client_secret=<secret> \
  -d 'scope=openid' \
  -d 'resource=http://localhost:8000/mcp/sentry' | jq -r .access_token)
curl -si $GW/mcp/sentry -H "Authorization: Bearer $NOSCOPE" | sed -n '1p;/WWW-Authenticate/p'
```

預期（challenge 帶 `insufficient_scope` + 缺的 scope）：

```text
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer resource_metadata="...", error="insufficient_scope", scope="email"
```

### Row 5b — audience 不符 → 401（安全關鍵）

兩條路由都開了 `require_audience: true`，各自預期 `aud` 等於
`gateway_origin + resource_path`。這列直接示範它擋下的攻擊——**跨資源重放**：
一顆綁定 gitea 的 token（第 Row 3 的 `$GOOD`），拿去打 sentry 一樣被擋：

```bash
curl -si $GW/mcp/sentry -H "Authorization: Bearer $GOOD" | sed -n '1p;$p'
# 預期 401 invalid_token（aud 綁 gitea，跨資源重放被擋）
```

再用**正確的 aud**（綁 sentry、scope 含 email）：

```bash
SENTRY=$(curl -s -X POST "$TOKEN_URL" \
  -d grant_type=client_credentials \
  -d client_id=<id> -d client_secret=<secret> \
  -d 'scope=email' \
  -d 'resource=http://localhost:8000/mcp/sentry' | jq -r .access_token)
curl -si $GW/mcp/sentry -H "Authorization: Bearer $SENTRY" | sed -n '1p;$p'
# 預期 200 hello from mcp-sentry
```

### Row 5c — HS256 偽造（alg confusion）→ 401（安全關鍵，免 token 來源）

plugin 把接受的演算法 pin 在 `RS256/384/512`，任何 `HS*` 一律拒絕——擋掉「拿
RSA 公鑰當 HMAC 密鑰簽 HS256」的經典偽造。用 openssl 手刻一顆 HS256：

```bash
header=$(printf '{"alg":"HS256","typ":"JWT","kid":"x"}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')
payload=$(printf '{"iss":"http://localhost:8080","scope":"email","exp":9999999999,"sub":"attacker"}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')
sig=$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -hmac "secret" -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
HS="$header.$payload.$sig"
curl -si $GW/mcp/gitea -H "Authorization: Bearer $HS" | sed -n '1p;$p'
```

預期（alg 先被擋，連 JWKS 都不會去抓）：

```text
HTTP/1.1 401 Unauthorized
{"error":"invalid_token","error_description":"invalid or expired access token"}
```

> **Row 4（過期 token）**：要真正過期得拿一顆短 TTL 的 token 等它到期，這取決於你
> AuthGate 的 access-token TTL 設定。若 AuthGate 允許簽短 TTL 的測試 token，鑄一顆
> 後 `sleep`（超過 ttl + `leeway_seconds: 60`）再打，預期 `401 invalid_token`。

---

## 10. 驗證身分 header 與防禦行為

### 10a. 偽造身分 header 會被覆寫（trust-header smuggling）

plugin 在轉發前會**先清掉** client 自帶的所有 `X-MCP-*` 身分 header（`Subject` /
`Scope` / `Issuer` / `Audience` / `Client` / `Token-Id` / `Expires`），再填入
**token 裡驗證過的**對應 claim（`sub` / `scope` 一定有，其餘視 token 是否帶該 claim
而定）。後端被告知「無條件信任這些 header」，所以這道清除是身分不被偽造的關鍵。下面
以 `X-MCP-Subject` / `X-MCP-Scope` 示範，其餘 header 同理。

stub 的 `http-echo` upstream 不會回放 header，要看到效果，臨時把 gitea upstream
換成會回放 header 的 echo 服務：

```bash
# 1) 在 Kong 的網路上起一個 header echo 容器
NET=$(docker inspect "$(docker-compose -f docker-compose.authgate.yml ps -q kong)" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}')
docker run -d --rm --name mcp-echo --network "$NET" mendhak/http-https-echo:31

# 2) 暫時把 kong.authgate.yml 的 gitea upstream 指到 echo，重建 kong
cp kong.authgate.yml /tmp/kong.authgate.yml.bak
sed -i '' 's#url: http://mcp-gitea:3000#url: http://mcp-echo:8080#' kong.authgate.yml
docker-compose -f docker-compose.authgate.yml up -d --force-recreate kong
sleep 8

# 3) 帶有效 token（Row 3 的 $GOOD），同時偽造 X-MCP-Subject / X-MCP-Scope
curl -s $GW/mcp/gitea \
  -H "Authorization: Bearer $GOOD" \
  -H "X-MCP-Subject: attacker@evil" \
  -H "X-MCP-Scope: admin:everything" \
  | python3 -c "import sys,json; h=json.load(sys.stdin)['headers']; print('x-mcp-subject ->', h.get('x-mcp-subject')); print('x-mcp-scope   ->', h.get('x-mcp-scope'))"
```

預期——偽造值被丟棄，換成 token 裡的真實身分（`sub` / `scope` 視你的 AuthGate 而定）：

```text
x-mcp-subject -> <token 裡的 sub>
x-mcp-scope   -> <token 裡的 scope>
```

還原設定、清掉 echo 容器：

```bash
cp /tmp/kong.authgate.yml.bak kong.authgate.yml
docker rm -f mcp-echo
docker-compose -f docker-compose.authgate.yml up -d --force-recreate kong
```

### 10b. 重複 Authorization header → 400

```bash
curl -si $GW/mcp/gitea \
  -H "Authorization: Bearer $GOOD" \
  -H "Authorization: token stolen-pat" | sed -n '1p'
# 預期 HTTP/1.1 400 Bad Request
```

> **觀察到的細節**：在 Kong 前面，底層 nginx 會在 plugin 執行**之前**就以 400
> 擋掉重複的 `Authorization` header（回應是 Kong 的通用 `{"message":"Bad request"}`、
> 帶 `Connection: close`、沒有 `WWW-Authenticate`）。plugin 內的多值檢查是
> **深度防禦**——在非 Kong 前置或 nginx 行為改變時才會由 plugin 自己回
> `400 invalid_request`。兩種情況都不會把未驗證的第二組憑證轉發出去。

### 10c. 垃圾 token → 401（不是 5xx）

```bash
curl -si $GW/mcp/gitea -H "Authorization: Bearer not.a.jwt" | sed -n '1p;$p'
# 預期 401 invalid_token
```

---

## 11. JWKS 失效時的行為（503，不是 401）

金鑰抓不到是 **gateway 端**的事，plugin 回 `503 temporarily_unavailable`（而非
401），這樣 spec-compliant 的 client 不會誤以為「token 壞了」去重跑整套 OAuth。
最直接的觀察是「placeholder 設定（[`kong.yml`](kong.yml) 的 `auth.example.com`
無 JWKS）下打 Row 3 會得到 503」；接真 AuthGate 時，停掉 AuthGate 後**既有金鑰
仍可用**，屬於正常的高可用設計（已抓到的金鑰每小時背景刷新、抓取逾時上限 10 秒、
失敗的抓取永不被 cache）。第 8 步的無帳密 probe 也是判斷 JWKS 連線的最快方式。

---

## 12. 收尾與清理

```bash
# 停掉 Kong demo stack
docker-compose -f docker-compose.authgate.yml down

# 移除編譯產物（已被 .gitignore 忽略）
rm -f mcp-oauth2 mcp-oauth2-linux
```

---

## 13. 常見問題（macOS）

| 症狀                                                                                         | 原因 / 解法                                                                                                                                                                                                                                                                                                                                                                                                                 |
| -------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `docker compose up --build` 卡在 `go mod download` 的 x509 憑證錯誤                          | 公司網路 TLS 攔截，BuildKit 容器內缺企業根憑證。改走本手冊第 2+7 步的本機交叉編譯 + `docker-compose.authgate.yml`。                                                                                                                                                                                                                                                                                                         |
| Row 3 一直 `503 temporarily_unavailable`                                                     | Kong 容器抓不到 `jwks_uri`。確認 AuthGate 在跑，且 `jwks_uri` 用 `host.docker.internal`（不是 `127.0.0.1` / `localhost`），且 compose 檔有 `extra_hosts: host.docker.internal:host-gateway`。用第 8 步的無帳密 probe 分辨連線問題。                                                                                                                                                                                         |
| Row 3 變成 `401 invalid_token`                                                               | 兩個常見原因：① `issuer` 設定值與 token 的 `iss` 不一致（差一個結尾斜線也會錯）；② token 的 `aud` 與 `gateway_origin + resource_path` 不符——取 token 時沒帶 `resource=`（見第 6 步）。解碼 token 比對 `iss` 和 `aud`，要逐字元相同。                                                                                                                                                                                        |
| token endpoint 回 `400 invalid_target`                                                       | 帶了 `resource=` 但該 URL 不在 client 的 `allowed_resources` 白名單（空白名單 = 全拒）。到 AuthGate 的 client 設定把資源 URL 加進 Allowed Resources。見第 6 步。                                                                                                                                                                                                                                                            |
| 有效 token 卻 `403 insufficient_scope`                                                       | `required_scopes` 要求了 AuthGate 沒發的 scope（例如 `mcp:gitea`，但 AuthGate 只有 `openid profile email`）。改成 AuthGate 真的會發的 scope，或在 AuthGate 端註冊該 scope。見第 5 步。                                                                                                                                                                                                                                      |
| `exec format error` / plugin 起不來                                                          | 交叉編譯的 `GOARCH` 跟 Docker VM 架構不符。Apple Silicon 用 `arm64`、Intel 用 `amd64`。                                                                                                                                                                                                                                                                                                                                     |
| Kong 啟動就掛在 `failed decoding plugin info: Expected value but found T_END at character 1` | Kong 跑 `QUERY_CMD`（`mcp-oauth2 -dump`）拿到**空 stdout**。先驗 binary：`docker-compose -f docker-compose.authgate.yml run --rm --entrypoint /usr/local/bin/mcp-oauth2 kong -dump` 應印出 `{"Protocol":"ProtoBuf:1",...}`。空白 / `exec format error` = binary 與 kong 容器架構錯位（見上一列）。用對的 `GOARCH` 重新交叉編譯（見第 2 步）再 `docker-compose -f docker-compose.authgate.yml up -d --force-recreate kong`。 |
| `docker compose` 說 unknown command                                                          | 你的環境只有獨立版 `docker-compose`。把指令裡的 `docker compose` 換成 `docker-compose` 即可（功能相同）。                                                                                                                                                                                                                                                                                                                   |
| 改了 `kong.authgate.yml` 沒生效                                                              | DB-less Kong 在啟動時讀設定。改完要 `docker-compose -f docker-compose.authgate.yml up -d --force-recreate kong`。                                                                                                                                                                                                                                                                                                           |

---

## 附錄：驗證結果速查

| #   | 測試                 | 指令重點                                                     | 預期                                     |
| --- | -------------------- | ------------------------------------------------------------ | ---------------------------------------- |
| 1   | 未認證挑戰           | `curl -si $GW/mcp/gitea`                                     | 401 + `WWW-Authenticate`                 |
| 2   | PRM 文件             | `curl -s $GW/.well-known/oauth-protected-resource/mcp/gitea` | JSON（resource / authorization_servers） |
| 3   | 有效 token           | `Bearer $GOOD`（resource 綁定 + scope 都要對）               | 200，轉發 upstream                       |
| 5a  | 缺 scope             | `Bearer $NOSCOPE`（aud 對、scope 錯）                        | 403 insufficient_scope                   |
| 5b  | audience 不符 / 相符 | 綁 gitea 的 token 打 sentry / 綁對 aud                       | 401 / 200                                |
| 5c  | HS256 偽造           | 手刻 HS256（免 token 來源）                                  | 401（alg confusion 被擋）                |
| 10a | 偽造身分 header      | 同時帶 `X-MCP-Subject: attacker`                             | 被覆寫成 token 的 `sub`                  |
| 10b | 重複 Authorization   | 兩個 `Authorization` header                                  | 400                                      |
| 10c | 垃圾 token           | `Bearer not.a.jwt`                                           | 401                                      |
| 8   | JWKS 連線 probe      | 手刻 RS256 垃圾簽章 token                                    | 401 = 連線 OK / 503 = JWKS 抓不到        |
