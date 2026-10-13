// Lock for the .NET session cache under concurrent handshakes.
//
// A Get result was copied into native memory with one allocator and freed with
// another (different heaps on Windows), and only the latest result was kept,
// freed by the next lookup. With several sessions looking up at once, one
// lookup could free another's result before the library had copied it, so a
// lookup read another key's value or freed memory. Sixteen fresh sessions per
// round resuming from one backend, with the GC running, exercise exactly that.
//
// The GC pressure also locks issue #89: on Linux the Go runtime moved
// CoreCLR's thread-suspension signal handler onto the alternate signal stack,
// which it overflows, and every run of this test died with SIGSEGV (exit 139)
// until Native restored the handler's flags.
//
// Run: dotnet run -- cache
using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using HttpCloak;

public static class TestSessionCache
{
    public static async Task<bool> RunAsync()
    {
        Console.WriteLine(new string('=', 60));
        Console.WriteLine("Session cache under concurrent handshakes");
        Console.WriteLine(new string('=', 60));

        using var server = new LocalHttpsServer();
        var url = $"https://127.0.0.1:{server.Port}/";

        var cache = new MemCache();
        using var backend = new SessionCacheBackend(cache);
        backend.Register();

        using var stop = new CancellationTokenSource();
        var gc = Task.Run(() =>
        {
            while (!stop.IsCancellationRequested)
            {
                GC.Collect();
                Thread.Sleep(2);
            }
        });

        var failed = 0;
        try
        {
            for (var round = 0; round < 20; round++)
            {
                var sessions = Enumerable.Range(0, 16)
                    .Select(_ => new Session(preset: "chrome-latest", httpVersion: "h1", verify: false))
                    .ToList();
                try
                {
                    var responses = await Task.WhenAll(sessions.Select(s => s.GetAsync(url)));
                    failed += responses.Count(r => r.StatusCode != 200);
                }
                finally
                {
                    foreach (var s in sessions) s.Dispose();
                }
            }
        }
        finally
        {
            stop.Cancel();
            await gc;
            backend.Unregister();
        }

        // Only the first round starts with an empty cache, so nearly every later
        // lookup should hit; a value garbled on the way out shows up as a miss.
        // The slack allows for one more round of misses.
        Console.WriteLine($"  gets {cache.Gets}, hits {cache.Hits}, puts {cache.Puts}, failed responses {failed}");
        var ok = failed == 0 && cache.Puts > 0 && cache.Hits >= cache.Gets - 2 * 16;
        Console.WriteLine(ok ? "  [PASS] Concurrent cache lookups" : "  [FAIL] Concurrent cache lookups");
        return ok;
    }

    sealed class MemCache : ISessionCache
    {
        readonly ConcurrentDictionary<string, string> _store = new();
        public int Gets, Hits, Puts;

        public string? Get(string key)
        {
            Interlocked.Increment(ref Gets);
            if (!_store.TryGetValue(key, out var value)) return null;
            Interlocked.Increment(ref Hits);
            return value;
        }

        public int Put(string key, string value, long ttlSeconds)
        {
            Interlocked.Increment(ref Puts);
            _store[key] = value;
            return 0;
        }

        public int Delete(string key)
        {
            _store.TryRemove(key, out _);
            return 0;
        }

        public string? GetEch(string key) => null;
        public int PutEch(string key, string value, long ttlSeconds) => 0;
        public void OnError(string operation, string key, string error) { }
    }

    // A minimal HTTPS server answering every request with "ok", so the test
    // needs no network and no tools outside the runtime.
    sealed class LocalHttpsServer : IDisposable
    {
        readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        readonly X509Certificate2 _cert;
        readonly CancellationTokenSource _stop = new();

        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

        public LocalHttpsServer()
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256);
            var san = new SubjectAlternativeNameBuilder();
            san.AddIpAddress(IPAddress.Loopback);
            request.CertificateExtensions.Add(san.Build());
            using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            _cert = X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx), null);
            _listener.Start();
            _ = AcceptLoop();
        }

        async Task AcceptLoop()
        {
            while (!_stop.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await _listener.AcceptTcpClientAsync(_stop.Token); }
                catch { return; }
                _ = Serve(client);
            }
        }

        async Task Serve(TcpClient client)
        {
            using (client)
            {
                try
                {
                    using var tls = new SslStream(client.GetStream());
                    await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                    {
                        ServerCertificate = _cert,
                        ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http11 },
                    });
                    var buffer = new byte[8192];
                    var seen = new StringBuilder();
                    while (!seen.ToString().Contains("\r\n\r\n"))
                    {
                        var n = await tls.ReadAsync(buffer);
                        if (n == 0) return;
                        seen.Append(Encoding.ASCII.GetString(buffer, 0, n));
                    }
                    var reply = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                    await tls.WriteAsync(reply);
                    await tls.FlushAsync();
                }
                catch
                {
                    // A client that goes away mid-handshake is not this test's concern.
                }
            }
        }

        public void Dispose()
        {
            _stop.Cancel();
            _listener.Stop();
            _cert.Dispose();
        }
    }
}
