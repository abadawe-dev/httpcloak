//! Check framing at the receiver after the Rust builder and C/Go boundary.
mod common;

use std::io::Read;
use std::sync::mpsc;
use std::time::Duration;

use common::*;
use httpcloak::{HttpVersion, Version};

#[test]
fn exact_headers_and_body_emit_one_length_on_http1() {
    for name in ["Content-Length", "content-length", "cOnTeNt-LeNgTh", ""] {
        let (tx, rx) = mpsc::channel();
        let server = RawServer::start(move |conn, _| {
            let mut body = [0; 18];
            conn.read_exact(&mut body).unwrap();
            tx.send(body).unwrap();
            write(conn, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        });
        let mut headers = vec![("User-Agent", "NativeSDK/1")];
        if !name.is_empty() {
            headers.push((name, "18"));
        }
        headers.push(("X-After", "tail"));
        let session = Session::builder().http_version(HttpVersion::Http1).timeout(Duration::from_secs(3)).build().unwrap();
        let response = session.post(server.url("/body")).exact_headers(headers).body(b"exact request body".to_vec()).send().unwrap();
        assert_eq!(response.version(), Version::HTTP_11);
        let head = server.next_head();
        println!("name={name:?}, wire={head:?}");
        let lengths: Vec<_> = head.lines().filter(|line| line.to_ascii_lowercase().starts_with("content-length:")).collect();
        let wire_name = if name.is_empty() { "Content-Length" } else { name };
        let expected = format!("{wire_name}: 18");
        assert_eq!(lengths, [expected.as_str()]);
        if !name.is_empty() {
            assert!(head.contains(&format!("{expected}\r\nX-After: tail")));
        }
        assert_eq!(rx.recv_timeout(Duration::from_secs(3)).unwrap(), *b"exact request body");
    }
}

#[test]
fn exact_headers_and_body_emit_one_length_on_http2() {
    let session = session();
    for name in ["Content-Length", "content-length", "cOnTeNt-LeNgTh", ""] {
        let mut headers = vec![("user-agent", "NativeSDK/1")];
        if !name.is_empty() {
            headers.push((name, "18"));
        }
        let response = session.post(https("/echo")).exact_headers(headers).body(b"exact request body".to_vec()).send().unwrap();
        assert_eq!(response.version(), Version::HTTP_2);
        let echoed = echo(&response);
        let lengths: Vec<_> = echoed["headers"].as_array().unwrap().iter().filter(|pair| pair[0] == "content-length").collect();
        println!("HTTP/2 name={name:?}, received={lengths:?}");
        assert_eq!(lengths.len(), 1);
        assert_eq!(lengths[0][1], "18");
        assert_eq!(echoed_body(&echoed), b"exact request body");
    }
}
