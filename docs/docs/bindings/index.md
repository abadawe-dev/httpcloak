---
title: Bindings
sidebar_position: 1
---

# Bindings

httpcloak ships in five languages. Go is the native implementation. Python, Node.js, .NET, and Kotlin on Android each call into the same cgo-built shared library, so the wire behaviour matches across all five surfaces.

## In this section

- [Go](./go): the native API, idiomatic Go
- [Python](./python): a `requests`-shaped wrapper over cgo
- [Node.js](./nodejs): koffi-backed, ESM and CJS both work
- [.NET](./dotnet): P/Invoke wrapper for .NET 8+
- [Android (Kotlin)](./android): coroutine-first Kotlin API over a thin JNI bridge
