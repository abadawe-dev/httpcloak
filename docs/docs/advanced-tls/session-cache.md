---
title: Distributed TLS Session Cache
sidebar_position: 7
---

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

# Distributed TLS Session Cache

`WithSessionCache(backend, errorCallback)` plugs a distributed store into a session's TLS ticket cache. By default, every `Session` keeps tickets in process memory. Across replicas, that means each worker pays a full TLS handshake on its first hit per host because no other worker's tickets are reachable. With a backend wired in, all replicas read and write to the same store and resumption tickets propagate across the fleet.

The backend stores TLS session tickets keyed by preset, protocol, host, and port. The value is a small JSON-shaped struct holding the base64 ticket, the base64 session state, and a creation timestamp. There's no plaintext request data in there, just what's needed to resume a TLS connection. ECH configs go through the same interface under a different key prefix when HTTP/3 is in play.

This is the standalone-session counterpart to `WithProxySessionCache` covered in [Local Proxy Server, distributed cache section](../recipes/local-proxy-server#distributed-tls-session-cache). The backend interface and key formats are identical. The difference is where it gets mounted: a `Session` you construct directly, vs. a `LocalProxy` instance.

## The interface

`SessionCacheBackend` lives in `transport/tls_cache.go`. Five methods:

```go
type SessionCacheBackend interface {
    Get(ctx context.Context, key string) (*TLSSessionState, error)
    Put(ctx context.Context, key string, session *TLSSessionState, ttl time.Duration) error
    Delete(ctx context.Context, key string) error
    GetECHConfig(ctx context.Context, key string) ([]byte, error)
    PutECHConfig(ctx context.Context, key string, config []byte, ttl time.Duration) error
}

type TLSSessionState struct {
    Ticket    string    `json:"ticket"`     // base64
    State     string    `json:"state"`      // base64
    CreatedAt time.Time `json:"created_at"`
}

type ErrorCallback func(operation string, key string, err error)
```

Error semantics:

- `Get` returns `(nil, nil)` for cache misses. A non-nil error gets reported via the error callback, the lib falls back to a full handshake on the connection.
- `Put` runs asynchronously. The TLS handshake doesn't wait on it. Errors fire the callback but never propagate up to the caller's request.
- `Delete` is rarely called by the lib in practice. Implement it correctly anyway, it gets used for invalidation paths.
- The ECH methods are only consulted on the H3 path. Returning `(nil, nil)` from both is fine if you only care about TLS resumption and not ECH config caching.

The error callback is advisory. Cache failures degrade silently to "full handshake on this connection", which is correct behavior. Pipe the callback into your logger or metrics sink and treat it as observability, not error handling.

## Redis-backed example

```go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "time"

    "github.com/redis/go-redis/v9"
    "github.com/sardanioss/httpcloak/transport"
)

type RedisCache struct {
    client *redis.Client
}

func (r *RedisCache) Get(ctx context.Context, key string) (*transport.TLSSessionState, error) {
    val, err := r.client.Get(ctx, key).Bytes()
    if err == redis.Nil {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }
    var state transport.TLSSessionState
    if err := json.Unmarshal(val, &state); err != nil {
        return nil, fmt.Errorf("decode session: %w", err)
    }
    return &state, nil
}

func (r *RedisCache) Put(ctx context.Context, key string, session *transport.TLSSessionState, ttl time.Duration) error {
    payload, err := json.Marshal(session)
    if err != nil {
        return err
    }
    return r.client.Set(ctx, key, payload, ttl).Err()
}

func (r *RedisCache) Delete(ctx context.Context, key string) error {
    return r.client.Del(ctx, key).Err()
}

func (r *RedisCache) GetECHConfig(ctx context.Context, key string) ([]byte, error) {
    val, err := r.client.Get(ctx, key).Bytes()
    if err == redis.Nil {
        return nil, nil
    }
    return val, err
}

func (r *RedisCache) PutECHConfig(ctx context.Context, key string, config []byte, ttl time.Duration) error {
    return r.client.Set(ctx, key, config, ttl).Err()
}
```

The shape matches `WithProxySessionCache` from the LocalProxy chapter. Same backend implementation works for both mounting points; you don't need separate types.

## Wiring it into a Session

```go
package main

import (
    "context"
    "log"

    "github.com/redis/go-redis/v9"
    "github.com/sardanioss/httpcloak"
)

func main() {
    rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
    backend := &RedisCache{client: rdb}

    errCb := func(op, key string, err error) {
        log.Printf("session cache: op=%s key=%s err=%v", op, key, err)
    }

    sess := httpcloak.NewSession("chrome-latest",
        httpcloak.WithSessionCache(backend, errCb),
        httpcloak.WithSessionTCPProxy("socks5://user:pass@residential.example:1080"),
    )
    defer sess.Close()

    resp, err := sess.Get(context.Background(), "https://example.com/")
    if err != nil {
        log.Fatal(err)
    }
    log.Println(resp.StatusCode, resp.Protocol)
}
```

The first request to `example.com` from a cold fleet pays a full handshake and writes a ticket into Redis. Every subsequent request from any worker on the same preset gets a 0-RTT or 1-RTT resumption against that ticket until the TTL expires. Default TTL is 24 hours, matching `transport.TLSSessionMaxAge`.

### Multiple sessions per process: SetSessionIdentifier

Two `Session` instances in the same process pointed at the same backend share the cache by default. If they target overlapping hostnames, they'll read each other's tickets. That's fine when both sessions use the same outbound proxy, the same source IP, and the same fingerprint preset. It is wrong when they don't, because TLS tickets bind to the connection that issued them. A ticket cut against `proxy-A` won't resume cleanly through `proxy-B`, and the visible failure mode is one session getting flagged on a target while the other inherits the bad reputation through a shared resumption.

`SetSessionIdentifier(id)` namespaces a session's cache keys. Cache key formats become `httpcloak:sessions:{id}:{preset}:{protocol}:{host}:{port}` instead of `httpcloak:sessions:{preset}:{protocol}:{host}:{port}`. Two sessions with different IDs never collide.

```go
alice := httpcloak.NewSession("chrome-latest",
    httpcloak.WithSessionCache(backend, errCb),
    httpcloak.WithSessionTCPProxy("socks5://user1:pass@residential.example:1080"),
)
alice.SetSessionIdentifier("alice")

bob := httpcloak.NewSession("chrome-latest",
    httpcloak.WithSessionCache(backend, errCb),
    httpcloak.WithSessionTCPProxy("socks5://user2:pass@residential.example:1080"),
)
bob.SetSessionIdentifier("bob")
```

For sessions registered into a `LocalProxy` via `RegisterSession(id, *Session)`, the identifier is set automatically. You only need to call `SetSessionIdentifier` manually when you're managing standalone sessions outside the proxy.

## How it differs from WithProxySessionCache

Same backend interface, same key formats, different mounting point.

| Option | Mounted on | Use case |
| --- | --- | --- |
| `WithSessionCache(backend, errCb)` | A standalone `*Session` | Direct httpcloak callers (Go services, scripts) sharing TLS state across replicas. |
| `WithProxySessionCache(backend, errCb)` | A `LocalProxy` instance | Cross-language clients routed through `LocalProxy`. The proxy fronts the cache for all languages. |

Picking between them is a deployment choice. Go services that import the library directly use `WithSessionCache`. Mixed-language fleets where Python, Node, or .NET workers route through a proxy use `WithProxySessionCache` on the proxy and don't touch the binding side. See [Local Proxy Server, distributed cache section](../recipes/local-proxy-server#distributed-tls-session-cache) for the proxy variant.

Both can coexist. A LocalProxy that registers per-tenant sessions can wire the cache at the proxy level (covers in-language clients hitting the proxy) and the registered standalone sessions inherit it through the same backend with the registry's automatic `SetSessionIdentifier` call doing the namespacing.

## Bindings

`WithSessionCache` on a per-`Session` basis is a Go-only API today. The interface accepts a Go interface value (`SessionCacheBackend`), which doesn't translate cleanly across the cgo boundary as a per-instance argument.

What the bindings do expose is a process-global cache backend:

- Python: `httpcloak.SessionCacheBackend(get=..., put=..., delete=..., on_error=...)` plus `.register()`. After `register()`, every `Session` and `LocalProxy` constructed in the process uses the registered backend. See `bindings/python/httpcloak/client.py` for the full signature.
- Node.js: `new SessionCacheBackend({ get, put, delete, onError })` plus `.register()`. Both sync and async callbacks supported. The callbacks are JavaScript, so they only run on the JS thread: use the async request methods with a cache configured. On a session created while a cache is set, the methods that block that thread (`*Sync`, streams, fast-path, `uploadStream`, `warmup`) throw an `HTTPCloakError`, since they would wait on a callback that can't run until they return.
- .NET: implement `ISessionCache` and pass it to `new SessionCacheBackend(impl)`, then call `Register()`. The wrapper pins the six callback delegates as instance fields so the GC can't collect them while the Go side still holds function pointers; `Dispose()` (or `using`) unregisters cleanly. `HttpCloakCache.ConfigureSessionCache(impl)` is a one-liner shorthand for construct+register, and `HttpCloakCache.ClearSessionCache()` drops the active backend.

```csharp
public sealed class RedisCache : ISessionCache
{
    private readonly IDatabase _db;
    public RedisCache(IDatabase db) => _db = db;
    public string? Get(string key) => _db.StringGet(key);
    public int Put(string key, string value, long ttl)
    {
        _db.StringSet(key, value, TimeSpan.FromSeconds(ttl));
        return 0;
    }
    public int Delete(string key) { _db.KeyDelete(key); return 0; }
    public void OnError(string op, string key, string err) => Log.Warn($"{op} {key}: {err}");
}

using var backend = new SessionCacheBackend(new RedisCache(redisDb));
backend.Register();
```

The process-global pattern works the same as the per-session call from the cache's perspective. Same key formats, same value shape, same TTL semantics. The only difference is registration scope. If you need different cache backends for different sessions in the same Python or Node or .NET process, the workaround is to run two LocalProxy processes, each with its own `WithProxySessionCache`, and route the right session through the right proxy.

For namespacing across multiple "personas" sharing one backend, the bindings expose `Session.set_session_identifier(id)` (Python) / `session.setSessionIdentifier(id)` (Node) / `Session.SetSessionIdentifier(id)` (.NET) and the `RegisterSession` method on `LocalProxy` calls it automatically.

## Operational notes

Latency: a backend `Get` runs synchronously on cache miss before the lib decides whether to attempt resumption. The transport hands the call a context with a 5-second deadline (set in `getFromBackend` in `transport/tls_cache.go`), and a Go backend that honors it falls back to a full handshake once it expires. A binding callback isn't interrupted, though: the handshake waits for it to return, however long that takes, so a callback that hangs stalls the request with it. Pick a backend that responds in single-digit milliseconds at p99. A slow backend turns into a tax on every cold-host request.

Writes are async. After a fresh handshake, the lib launches a goroutine that calls `Put` on the backend with a 5-second timeout. The request's response time isn't affected by backend write latency. Errors on `Put` fire the error callback and get dropped, since there's no caller to return them to. That's fine in practice (the next replica that needs the ticket will just do a fresh handshake), but it does mean you can't observe write failures except through the callback.

TTL: the lib passes 24 hours to `Put` (the value of `transport.TLSSessionMaxAge`). Pick a backend that honors per-key TTL. Redis does, Memcached does, a naive in-memory map doesn't unless you wrap it.

Concurrency: `Get` and `Put` can be called from any goroutine, often concurrently. The interface contract requires implementations to be safe for concurrent use. Most Redis / Memcached client libraries handle that for free.

Capacity: the local in-process cache evicts at 32 entries (`TLSSessionCacheMaxSize`). The backend has no such limit, so cross-replica sharing keeps tickets alive longer than any single replica's local view. A worker that hasn't talked to a host in a week will still get resumption if some other worker handled it within the TTL window.

Observability: wire the error callback into your metrics layer with operation as a label (`get`, `put`, `put_serialize`, etc). A spike on `put` errors usually means Redis is back-pressured or out of memory. A spike on `get` with a non-zero hit rate elsewhere usually means a network split between the worker and the backend. Empty error stream plus low resumption rate means your TTL is too short or the keys aren't matching across replicas (check that all replicas use the same preset string, since the preset is part of the key).

## Direct `PersistableSessionCache` use

Most callers wire a backend through `WithSessionCache` and never touch the cache type directly. For the cases that need it (custom transports, tooling that pre-populates the cache from a saved snapshot, tests that want to inject and inspect tickets), the type lives in `transport/tls_cache.go`:

```go
import "github.com/sardanioss/httpcloak/transport"

cache := transport.NewPersistableSessionCache()
// or build one with the backend already attached:
cache := transport.NewPersistableSessionCacheWithBackend(backend, preset, protocol, errCb)

cache.SetBackend(backend, preset, protocol, errCb) // attach or swap the backend at runtime
cache.SetSessionIdentifier("alice")                 // namespace the keys
id := cache.GetSessionIdentifier()
cache.SetErrorCallback(newCb)                       // hot-swap the error sink
```

`NewPersistableSessionCache()` takes no arguments; the constructor builds a per-process in-memory cache that satisfies the stdlib `tls.ClientSessionCache` interface. The `(backend, preset, protocol, errorCallback)` set is supplied separately by the with-backend constructor or `SetBackend`, and that's where the cache key namespacing comes from. The `protocol` argument is one of `"h1"`, `"h2"`, `"h3"`, matching the wire-protocol slot a ticket binds to. Mixing protocols in one cache instance isn't supported; each protocol gets its own `PersistableSessionCache` under the hood, and `WithSessionCache` builds them in pairs (or triples when H3 is in play) for you.

The cache also implements the stdlib `Get(sessionKey)` / `Put(sessionKey, *ClientSessionState)` methods that `*tls.Config.ClientSessionCache` expects, so pointing a fresh `*tls.Config` at one for unit tests is straightforward.

## Picking a backend

Redis is the obvious default. It does per-key TTL, it's fast, and the `go-redis` client handles pipelining and reconnection. For a fleet under a few hundred RPS at peak, a single Redis instance is enough. Past that, look at Redis Cluster or a sharded setup, since the workload is mostly small reads and writes that distribute well across keys.

Memcached works too. The interface is simpler, the wire protocol is tighter, and TTL semantics are identical for this use case. The downside is the `Delete` path is rarely hit, so a cache that does aggressive LRU eviction (which Memcached does, Redis with `noeviction` doesn't) might lose tickets you'd rather keep.

A flat file or local SQLite is a fine choice for single-host deployments where you only want persistence across restarts, not cross-replica sharing. It's not what `WithSessionCache` was built for, but the interface doesn't care; it just calls `Get` / `Put` and trusts the implementation. Watch for write contention if you have many sessions writing concurrently.

Whatever backend you pick, the value is small (a base64 ticket plus a base64 session state, typically a few hundred bytes), and reads outnumber writes by a wide margin once the fleet has been running for a few minutes. Sizing is rarely the bottleneck. Latency and availability are what matter, since a backend that's unavailable degrades the fleet to "every cold-host request pays a full handshake" instead of breaking it outright.

The error callback can also drive a circuit breaker if the backend keeps failing. Track the rate of `get` errors over a rolling window, and once it crosses a threshold, swap the cache backend on the underlying `PersistableSessionCache` via `SetBackend(backend SessionCacheBackend, preset, protocol string, errorCallback ErrorCallback)`. Passing `nil` for the backend reverts to local-only ticket caching while the real backend recovers, then you swap the live backend back in once health checks pass. The other three arguments stay as the original session's preset, protocol and callback so cache key namespacing is preserved across the swap.
