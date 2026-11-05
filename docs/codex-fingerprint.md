# Codex 指纹优化

本文档描述了 magpie 如何通过伪装指纹来避免被 Cloudflare 等防护系统识别。

## 问题背景

当 Codex CLI 通过 magpie 网关访问 OpenAI 的 ChatGPT 后端时，可能会遇到 403 Forbidden 错误，返回 Cloudflare 的拦截页面：

```
Unable to load site
Please try again later. If you are using a VPN, try turning it off.
```

这是因为 magpie 的 HTTP client 指纹与 Codex 官方客户端不同，被 Cloudflare 识别为机器人。

## 参考源码

本优化基于 [OpenAI Codex CLI](https://github.com/openai/codex) 的开源代码：

- **`codex-rs/login/src/auth/default_client.rs`** - User-Agent 生成逻辑
- **`codex-rs/http-client/src/client_builder.rs`** - HTTP client 配置
- **`codex-rs/terminal-detection/src/lib.rs`** - 终端检测逻辑

## 指纹特征

### 1. TLS 指纹

**Codex 官方客户端**（来自 [openai/codex](https://github.com/openai/codex)）：
- 使用 Rust 的 reqwest 库，默认使用 rustls
- 使用 rustls 的默认 cipher suites 和曲线（来自 `rustls::crypto::aws_lc_rs::default_provider`）
- 支持 TLS 1.2 和 1.3
- 代码位置：`codex-rs/http-client/src/client_builder.rs`

**rustls 默认配置**：
```rust
// From rustls::crypto::aws_lc_rs::default_provider()
CipherSuites: [
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
    // ...
]
Curves: [
    X25519,
    secp256r1,
    secp384r1,
]
```

**magpie 优化后**：
- 使用 Go 的 crypto/tls，配置为 rustls 的默认指纹
- rustls 和 Chrome 都使用 BoringSSL/aws-lc-rs，所以指纹相似

```go
CipherSuites: []uint16{
    tls.TLS_AES_128_GCM_SHA256,
    tls.TLS_AES_256_GCM_SHA384,
    tls.TLS_CHACHA20_POLY1305_SHA256,
    // ...
}
CurvePreferences: []tls.CurveID{
    tls.X25519,
    tls.CurveP256,
    tls.CurveP384,
}
```

### 2. HTTP 版本

**Codex 官方客户端**：
- 强制使用 HTTP/1.1（因为 HTTP/2 连接有问题）
- 或者使用 WebSocket
- 代码位置：`codex-rs/http-client/src/client_builder.rs`

**magpie 优化后**：
- 保持 HTTP/1.1（与 Codex 一致）
- 但优化 HTTP/2 配置以备将来使用

### 3. 请求头

**Codex 官方客户端**（来自 `codex-rs/login/src/auth/default_client.rs`）：
```
User-Agent: codex_cli_rs/0.163.0 (Mac OS 15.8.1; arm64) iTerm.app/3.5.0
Accept: application/json
Accept-Language: en-US,en;q=0.9
Cache-Control: no-cache
Pragma: no-cache
originator: codex_cli_rs
```

**User-Agent 格式**：
```rust
format!(
    "{}/{build_version} ({} {}; {}) {}",
    originator.value.as_str(),  // "codex_cli_rs"
    os_info.os_type(),          // "Mac OS"
    os_info.version(),          // "15.8.1"
    os_info.architecture(),     // "arm64"
    user_agent()                // "iTerm.app/3.5.0"
)
```

**Go 的默认指纹**：
Go 的 `net/http` 默认会发送以下指纹特征，会暴露我们是 Go 程序：
```
User-Agent: Go-http-client/1.1
Accept-Encoding: gzip
```

**magpie 优化后**：
- **移除 Go 的默认指纹**：
  - 替换 `User-Agent: Go-http-client/1.1` 为 Codex 的格式
  - 移除 `Accept-Encoding: gzip`（让 transport 处理）
- **智能指纹选择**：根据请求来源决定是否使用伪装指纹
  - **Codex 客户端**：使用 Codex 的真实指纹（rustls）
  - **非 Codex 客户端**：使用伪装的 Codex 指纹（避免被识别为机器人）
- 透传 Codex 的 User-Agent，或生成匹配的格式
- 添加缺失的 Accept、Accept-Language、Cache-Control、Pragma
- 添加 originator 头
- 移除可能暴露 magpie 的自定义头

### 4. 连接行为

**Codex 官方客户端**：
- 使用 reqwest 的默认连接池配置
- 支持 HTTP/2（但对 ChatGPT 后端禁用）
- TCP keep-alive

**magpie 优化后**：
```go
MaxIdleConnsPerHost:   16,
IdleConnTimeout:       120 * time.Second,
DialContext: (&net.Dialer{
    Timeout:   30 * time.Second,
    KeepAlive: 30 * time.Second,
}).DialContext,
```

## 实现

### 文件

- `internal/gateway/codex_fingerprint.go` - 指纹配置（包括 uTLS 集成和智能指纹选择）
- `internal/gateway/codex_fingerprint_test.go` - 测试
- `internal/gateway/upstream_transport.go` - 应用指纹配置
- `internal/gateway/codex_backend.go` - 应用请求头优化

### 关键函数

#### `codexTLSConfig()`

返回 rustls 的默认 TLS 指纹配置（使用 Go 的 crypto/tls）。

#### `codexUTLSConfig()`

返回 rustls 的默认 TLS 指纹配置（使用 uTLS，更准确）。

#### `codexUTLSClientHelloID()`

返回匹配 rustls 的 ClientHelloID（使用 Chrome 的指纹，因为两者都基于 BoringSSL/aws-lc-rs）。

#### `codexUTLSDialer()`

返回使用 uTLS 进行 TLS 握手的 DialContext 函数。

#### `codexHTTP2Config()`

返回 Codex CLI 的 HTTP/2 配置。

#### `codexTransport(wait time.Duration)`

返回配置了指纹伪装的 http.Transport（使用标准 crypto/tls）。

#### `codexTransportWithUTLS(wait time.Duration)`

返回配置了指纹伪装的 http.Transport（使用 uTLS，更准确）。

#### `mimicCodexHeaders(h http.Header)`

调整请求头以匹配 Codex CLI。

#### `isCodexClient(r *http.Request)`

判断请求是否来自 Codex CLI 本身。

#### `buildCodexUserAgent()`

构建匹配 Codex CLI 格式的 User-Agent 字符串。

## 测试

运行指纹测试：

```bash
go test ./internal/gateway -run "TestCodexTLS|TestCodexHTTP2|TestMimicCodexHeaders|TestCodexTransport" -v
```

## 验证

### 1. 本地测试

```bash
# 直接请求（不通过 magpie）
curl -v -X POST https://chatgpt.com/backend-api/codex/responses \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --http1.1 \
  -d @request.json

# 通过 magpie 请求
curl -v -X POST http://127.0.0.1:3425/backend-api/codex/responses \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @request.json
```

### 2. 生产环境

1. 部署优化后的 magpie
2. 观察 403 错误是否减少
3. 监控 Cloudflare 的拦截率

## 智能指纹选择

magpie 会根据请求来源智能选择是否使用伪装指纹：

### Codex 客户端

当请求来自 Codex CLI 本身时（通过 User-Agent 判断），magpie 会使用 Codex 的真实指纹（rustls），而不是伪装指纹。这样可以：

1. **保持兼容性**：Codex 客户端与 OpenAI 后端之间的通信保持原样
2. **避免冲突**：不会因为指纹伪装而导致 Codex 客户端无法正常工作
3. **提高真实性**：Codex 客户端的请求看起来更真实

### 非 Codex 客户端

当请求来自其他客户端（如 Claude Code、Cursor 等）但使用 Codex 模型时，magpie 会使用伪装的 Codex 指纹。这样可以：

1. **避免检测**：防止被 Cloudflare 等防护系统识别为机器人
2. **提高成功率**：减少 403 Forbidden 错误
3. **保持一致性**：所有使用 Codex 模型的请求都使用相同的指纹

### 判断逻辑

```go
func isCodexClient(r *http.Request) bool {
    ua := r.Header.Get("User-Agent")
    return strings.HasPrefix(ua, "codex_cli_rs/") ||
        strings.Contains(strings.ToLower(ua), "codex")
}
```

### 示例

| 客户端 | User-Agent | 使用指纹 |
|--------|-----------|---------|
| Codex CLI | `codex_cli_rs/0.163.0 (Mac OS 15.8.1; arm64) iTerm.app/3.5.0` | Codex 真实指纹 |
| Claude Code | `claude-cli/1.0.0` | 伪装 Codex 指纹 |
| Cursor | `Cursor/0.1.0` | 伪装 Codex 指纹 |
| 其他 | `Mozilla/5.0 ...` | 伪装 Codex 指纹 |

## 502 错误重试

magpie 支持在路由规则中配置当 Codex 返回 502 Bad Gateway 错误时，在原账号上重试而不是切换到下一个账号。

### 配置方法

在路由规则中设置 `retryOn502` 字段：

```json
{
  "use": "codex/gpt-4",
  "retryOn502": true
}
```

### 工作原理

1. **默认行为**：当 Codex 返回 502 错误时，magpie 会认为账号过载，并切换到下一个账号
2. **启用 `retryOn502`**：当 Codex 返回 502 错误时，magpie 会在原账号上重试，而不是切换账号

### 使用场景

- **Codex 后端繁忙**：当 Codex 后端暂时繁忙时，502 错误可能是暂时的，重试可能会成功
- **避免账号切换**：在某些情况下，频繁切换账号可能会导致更多的问题
- **提高成功率**：对于某些暂时性的 502 错误，重试可能会成功

### 注意事项

1. **仅适用于 502 错误**：`retryOn502` 只影响 502 Bad Gateway 错误，其他错误（如 429、503）仍然会使用默认的重试逻辑
2. **重试次数**：重试次数仍然受到 `lastRetries` 的限制
3. **超时**：重试仍然会受到请求超时的限制

## 使用 uTLS

### 默认行为

默认情况下，magpie 使用 Go 的标准 `crypto/tls` 库，配置为 rustls 的指纹。这已经足够接近 Codex 的指纹，可以通过大多数防护系统。

### 启用 uTLS

如果需要更准确的指纹伪装，可以启用 uTLS：

```go
// 在 codex_backend.go 中
transport := codexTransportWithUTLS(upstreamHeaderWait)
```

### uTLS 的优势

1. **更准确的指纹**：uTLS 可以完全模拟 rustls 的 ClientHello，包括扩展的顺序和内容。
2. **灵活性**：可以轻松切换不同的指纹（Chrome、Firefox、Safari 等）。
3. **抗检测**：uTLS 专门设计用于抗 TLS 指纹检测。

### uTLS 的劣势

1. **性能**：uTLS 的握手可能比标准库慢一些。
2. **维护**：需要跟踪 uTLS 库的更新。
3. **兼容性**：某些服务器可能不支持 uTLS 的某些扩展。

### 建议

- **默认**：使用标准 `crypto/tls`（`codexTransport`）
- **高风险环境**：使用 uTLS（`codexTransportWithUTLS`）
- **测试环境**：使用标准 `crypto/tls`，因为 uTLS 可能与测试服务器不兼容

## 注意事项

1. **HTTP/1.1 vs HTTP/2**：由于 Codex 后端的已知问题，我们保持 HTTP/1.1。如果将来问题解决，可以考虑启用 HTTP/2。

2. **TLS 指纹**：当前使用 Chrome 的指纹。如果需要更精确的伪装，可以考虑使用 uTLS 库模拟 rustls 的指纹。

3. **请求头**：确保 User-Agent 与实际使用的 Codex CLI 版本匹配。

4. **连接池**：增大连接池可能会增加内存使用，但可以提高性能。

## 未来改进

1. **uTLS 集成**：✅ 已实现 - 使用 `github.com/refraction-networking/utls` 库完全模拟 rustls 的 TLS 指纹。

2. **动态指纹**：根据不同的防护系统动态调整指纹。

3. **指纹轮换**：定期更换指纹以避免被标记。

4. **WebSocket 支持**：完全支持 Codex 的 WebSocket 协议，避免 HTTP 回退。

5. **终端检测**：实现完整的终端检测逻辑，匹配 Codex 的 `terminal-detection` crate。

## 相关 Issue

- #3184 - Codex WebSocket 转发问题
- #2354 - Codex 通过 magpie 变慢的问题

