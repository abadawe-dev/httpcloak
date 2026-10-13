using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace HttpCloak;

/// <summary>
/// Implement this to plug a distributed TLS session cache (Redis, Memcached,
/// SQL, whatever) into HttpCloak. The cache is consulted on every TLS handshake
/// so multiple processes can share resumption tickets and skip the full TLS
/// negotiation on subsequent connects.
///
/// The callbacks run on the Go-side I/O thread that owns the handshake; keep
/// them fast and non-blocking. Long-running backend operations (e.g. a real
/// Redis round-trip) should ideally use the async cache API once it ships in
/// .NET; for now, point the sync interface at a fast local store or accept the
/// latency on every connect.
///
/// All keys are namespaced by HttpCloak (e.g.
/// <c>httpcloak:sessions:{preset}:{protocol}:{host}:{port}</c>); the
/// implementation should treat keys as opaque strings.
/// </summary>
public interface ISessionCache
{
    /// <summary>
    /// Look up a TLS session by key. Return the JSON-serialised session state,
    /// or <c>null</c> if the key is not present.
    /// </summary>
    string? Get(string key);

    /// <summary>
    /// Store a TLS session under the given key with a TTL hint (seconds).
    /// Return 0 on success, non-zero to signal an error to the cache layer.
    /// </summary>
    int Put(string key, string valueJson, long ttlSeconds);

    /// <summary>
    /// Remove a TLS session by key. Return 0 on success.
    /// </summary>
    int Delete(string key);

    /// <summary>
    /// Look up a stored ECH config by key. Return the base64-encoded config,
    /// or <c>null</c> if the key is not present. Default implementation
    /// returns <c>null</c> (no ECH caching).
    /// </summary>
    string? GetEch(string key) => null;

    /// <summary>
    /// Store an ECH config under the given key with a TTL hint (seconds).
    /// Return 0 on success. Default implementation no-ops and returns 0.
    /// </summary>
    int PutEch(string key, string valueBase64, long ttlSeconds) => 0;

    /// <summary>
    /// Fired when the cache layer reports a backend error. Implementations
    /// should log, surface to telemetry, etc. The session continues; ECH /
    /// resumption simply falls back to fresh handshakes for that key.
    /// Default implementation no-ops.
    /// </summary>
    void OnError(string operation, string key, string error) { }
}

/// <summary>
/// Managed wrapper around the distributed TLS session cache callback surface.
/// Construct with an <see cref="ISessionCache"/>, call <see cref="Register"/>
/// to wire it into the native library globally, and <see cref="Dispose"/> or
/// <see cref="Unregister"/> when done.
///
/// Only one backend can be active per process; <see cref="Register"/> on a
/// second instance replaces the first. The wrapper keeps the delegates pinned
/// as instance fields so they survive across native calls without being
/// collected.
/// </summary>
/// <example>
/// <code>
/// public sealed class RedisCache : ISessionCache
/// {
///     private readonly IDatabase _db = /* StackExchange.Redis IDatabase */;
///     public string? Get(string key) =&gt; _db.StringGet(key);
///     public int Put(string key, string value, long ttl)
///     {
///         _db.StringSet(key, value, TimeSpan.FromSeconds(ttl));
///         return 0;
///     }
///     public int Delete(string key) { _db.KeyDelete(key); return 0; }
///     public void OnError(string op, string key, string err) =&gt; Log.Error($"{op} {key}: {err}");
/// }
///
/// using var backend = new SessionCacheBackend(new RedisCache());
/// backend.Register();
/// // ... use Session normally ...
/// </code>
/// </example>
public sealed class SessionCacheBackend : IDisposable
{
    private readonly ISessionCache _impl;

    // Pinned delegate instances. Held in fields so the GC doesn't collect
    // them while the Go side still holds function pointers into them.
    private readonly Native.SessionCacheGetCallback _getCb;
    private readonly Native.SessionCachePutCallback _putCb;
    private readonly Native.SessionCacheDeleteCallback _deleteCb;
    private readonly Native.EchCacheGetCallback _echGetCb;
    private readonly Native.EchCachePutCallback _echPutCb;
    private readonly Native.SessionCacheErrorCallback _errorCb;

    // Native buffers for recent Get / GetEch results. The native side copies
    // the returned string right after the thunk returns and never frees it,
    // so the wrapper owns the buffer. One slot freed by the next call is not
    // enough: a single backend serves every session, and a Get on another
    // thread could free the buffer before this caller's copy is taken. The
    // last RetainedBuffers results stay alive instead and the oldest is
    // freed as each new one arrives, the same bounded ring the Python
    // binding keeps.
    private const int RetainedBuffers = 128;
    private readonly IntPtr[] _retained = new IntPtr[RetainedBuffers];
    private int _retainedNext;
    private readonly object _ptrLock = new();

    // Single-process registration guard.
    private static readonly object _registrationLock = new();
    private static SessionCacheBackend? _activeBackend;
    private bool _registered;
    private bool _disposed;

    public SessionCacheBackend(ISessionCache impl)
    {
        _impl = impl ?? throw new ArgumentNullException(nameof(impl));
        _getCb = GetThunk;
        _putCb = PutThunk;
        _deleteCb = DeleteThunk;
        _echGetCb = GetEchThunk;
        _echPutCb = PutEchThunk;
        _errorCb = ErrorThunk;
    }

    /// <summary>
    /// Activate this backend globally. Subsequent TLS handshakes from any
    /// <see cref="Session"/> in the process will consult the underlying
    /// <see cref="ISessionCache"/>. If another <see cref="SessionCacheBackend"/>
    /// is already registered, it is unregistered first.
    /// </summary>
    public void Register()
    {
        ThrowIfDisposed();
        lock (_registrationLock)
        {
            if (_activeBackend != null && !ReferenceEquals(_activeBackend, this))
            {
                _activeBackend.UnregisterUnlocked();
            }
            Native.SetSessionCacheCallbacks(
                _getCb, _putCb, _deleteCb,
                _echGetCb, _echPutCb,
                _errorCb);
            _activeBackend = this;
            _registered = true;
        }
    }

    /// <summary>
    /// Deactivate this backend globally. After this call new TLS handshakes
    /// fall back to the library's built-in in-memory cache. Safe to call when
    /// not registered.
    /// </summary>
    public void Unregister()
    {
        lock (_registrationLock)
        {
            UnregisterUnlocked();
        }
    }

    private void UnregisterUnlocked()
    {
        if (!_registered) return;
        Native.ClearSessionCacheCallbacks();
        if (ReferenceEquals(_activeBackend, this))
        {
            _activeBackend = null;
        }
        _registered = false;
    }

    /// <summary>
    /// Whether this backend is currently the active global cache.
    /// </summary>
    public bool IsRegistered => _registered;

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Unregister();
        FreeLastBuffers();
        GC.SuppressFinalize(this);
    }

    ~SessionCacheBackend()
    {
        if (!_disposed)
        {
            try { Unregister(); } catch { /* finalizer */ }
            FreeLastBuffers();
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(SessionCacheBackend));
    }

    private void FreeLastBuffers()
    {
        lock (_ptrLock)
        {
            for (int i = 0; i < _retained.Length; i++)
            {
                if (_retained[i] != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(_retained[i]);
                    _retained[i] = IntPtr.Zero;
                }
            }
        }
    }

    // Copies value into a native UTF-8 buffer that stays alive until
    // RetainedBuffers more results have been handed out. CoTaskMem has to be
    // released with FreeCoTaskMem; on Windows FreeHGlobal is a different heap.
    private IntPtr Retain(string value)
    {
        IntPtr ptr = Marshal.StringToCoTaskMemUTF8(value);
        lock (_ptrLock)
        {
            IntPtr oldest = _retained[_retainedNext];
            if (oldest != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(oldest);
            }
            _retained[_retainedNext] = ptr;
            _retainedNext = (_retainedNext + 1) % RetainedBuffers;
        }
        return ptr;
    }

    // -------------------------------------------------------------------
    // Native callback thunks. The Go side passes raw const char* pointers,
    // so each thunk marshals manually via Marshal.PtrToStringUTF8. All
    // exceptions are swallowed and turned into "not found" / non-zero
    // results so a crashing user implementation never propagates into Go.
    // -------------------------------------------------------------------

    private IntPtr GetThunk(IntPtr keyPtr)
    {
        try
        {
            string key = Marshal.PtrToStringUTF8(keyPtr) ?? string.Empty;
            string? value = _impl.Get(key);
            if (value == null) return IntPtr.Zero;
            return Retain(value);
        }
        catch
        {
            return IntPtr.Zero;
        }
    }

    private int PutThunk(IntPtr keyPtr, IntPtr valuePtr, long ttlSeconds)
    {
        try
        {
            string key = Marshal.PtrToStringUTF8(keyPtr) ?? string.Empty;
            string value = Marshal.PtrToStringUTF8(valuePtr) ?? string.Empty;
            return _impl.Put(key, value, ttlSeconds);
        }
        catch
        {
            return -1;
        }
    }

    private int DeleteThunk(IntPtr keyPtr)
    {
        try
        {
            string key = Marshal.PtrToStringUTF8(keyPtr) ?? string.Empty;
            return _impl.Delete(key);
        }
        catch
        {
            return -1;
        }
    }

    private IntPtr GetEchThunk(IntPtr keyPtr)
    {
        try
        {
            string key = Marshal.PtrToStringUTF8(keyPtr) ?? string.Empty;
            string? value = _impl.GetEch(key);
            if (value == null) return IntPtr.Zero;
            return Retain(value);
        }
        catch
        {
            return IntPtr.Zero;
        }
    }

    private int PutEchThunk(IntPtr keyPtr, IntPtr valuePtr, long ttlSeconds)
    {
        try
        {
            string key = Marshal.PtrToStringUTF8(keyPtr) ?? string.Empty;
            string value = Marshal.PtrToStringUTF8(valuePtr) ?? string.Empty;
            return _impl.PutEch(key, value, ttlSeconds);
        }
        catch
        {
            return -1;
        }
    }

    private void ErrorThunk(IntPtr opPtr, IntPtr keyPtr, IntPtr errorPtr)
    {
        try
        {
            string op = Marshal.PtrToStringUTF8(opPtr) ?? string.Empty;
            string key = Marshal.PtrToStringUTF8(keyPtr) ?? string.Empty;
            string err = Marshal.PtrToStringUTF8(errorPtr) ?? string.Empty;
            _impl.OnError(op, key, err);
        }
        catch
        {
            // OnError is best-effort; if user code throws, swallow it.
        }
    }

    /// <summary>
    /// Convenience static: clear any currently-registered cache backend.
    /// Equivalent to disposing the active <see cref="SessionCacheBackend"/>.
    /// </summary>
    public static void ClearActive()
    {
        lock (_registrationLock)
        {
            _activeBackend?.UnregisterUnlocked();
            // Even if no managed wrapper is tracked, drop any stale callbacks
            // from the native side (defensive against external registrations).
            Native.ClearSessionCacheCallbacks();
            _activeBackend = null;
        }
    }
}

/// <summary>
/// Top-level convenience helpers for the distributed cache surface.
/// Mirrors Python's <c>httpcloak.configure_session_cache()</c> /
/// <c>httpcloak.clear_session_cache()</c>.
/// </summary>
public static class HttpCloakCache
{
    /// <summary>
    /// Wire the given <see cref="ISessionCache"/> implementation in as the
    /// active distributed cache backend. Returns the managed wrapper so the
    /// caller can <see cref="SessionCacheBackend.Unregister"/> or
    /// <see cref="SessionCacheBackend.Dispose"/> when done.
    /// </summary>
    public static SessionCacheBackend ConfigureSessionCache(ISessionCache impl)
    {
        var backend = new SessionCacheBackend(impl);
        backend.Register();
        return backend;
    }

    /// <summary>
    /// Drop the currently active distributed cache backend, if any. Subsequent
    /// TLS handshakes fall back to the library's built-in in-memory cache.
    /// </summary>
    public static void ClearSessionCache() => SessionCacheBackend.ClearActive();
}
