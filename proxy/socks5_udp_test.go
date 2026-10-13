package proxy

import (
	"bytes"
	"net"
	"testing"
)

func TestBuildSOCKS5UDPHeader_IPv4(t *testing.T) {
	tests := []struct {
		name     string
		addr     *net.UDPAddr
		expected []byte
	}{
		{
			name: "simple IPv4",
			addr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 443},
			expected: []byte{
				0x00, 0x00, 0x00, // RSV + FRAG
				0x01,       // ATYP: IPv4
				1, 2, 3, 4, // IP
				0x01, 0xBB, // Port 443 (big-endian)
			},
		},
		{
			name: "localhost IPv4",
			addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
			expected: []byte{
				0x00, 0x00, 0x00,
				0x01,
				127, 0, 0, 1,
				0x1F, 0x90, // Port 8080
			},
		},
		{
			name: "port 80",
			addr: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 80},
			expected: []byte{
				0x00, 0x00, 0x00,
				0x01,
				192, 168, 1, 1,
				0x00, 0x50, // Port 80
			},
		},
		{
			name: "high port",
			addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 65535},
			expected: []byte{
				0x00, 0x00, 0x00,
				0x01,
				10, 0, 0, 1,
				0xFF, 0xFF, // Port 65535
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildSOCKS5UDPHeader(tt.addr)
			if !bytes.Equal(got, tt.expected) {
				t.Errorf("buildSOCKS5UDPHeader() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestBuildSOCKS5UDPHeader_IPv6(t *testing.T) {
	tests := []struct {
		name     string
		addr     *net.UDPAddr
		expected []byte
	}{
		{
			name: "localhost IPv6",
			addr: &net.UDPAddr{IP: net.ParseIP("::1"), Port: 443},
			expected: []byte{
				0x00, 0x00, 0x00, // RSV + FRAG
				0x04,                                           // ATYP: IPv6
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // ::1
				0x01, 0xBB, // Port 443
			},
		},
		{
			name: "full IPv6",
			addr: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 80},
			expected: []byte{
				0x00, 0x00, 0x00,
				0x04,
				0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
				0x00, 0x50, // Port 80
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildSOCKS5UDPHeader(tt.addr)
			if !bytes.Equal(got, tt.expected) {
				t.Errorf("buildSOCKS5UDPHeader() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParseSOCKS5UDPHeader_IPv4(t *testing.T) {
	tests := []struct {
		name       string
		packet     []byte
		wantOffset int
		wantIP     net.IP
		wantPort   int
		wantErr    bool
	}{
		{
			name: "valid IPv4",
			packet: []byte{
				0x00, 0x00, 0x00, // RSV + FRAG
				0x01,       // ATYP: IPv4
				1, 2, 3, 4, // IP
				0x01, 0xBB, // Port 443
				'H', 'e', 'l', 'l', 'o', // Data
			},
			wantOffset: 10,
			wantIP:     net.ParseIP("1.2.3.4"),
			wantPort:   443,
			wantErr:    false,
		},
		{
			name: "valid IPv4 no data",
			packet: []byte{
				0x00, 0x00, 0x00,
				0x01,
				192, 168, 1, 1,
				0x1F, 0x90,
			},
			wantOffset: 10,
			wantIP:     net.ParseIP("192.168.1.1"),
			wantPort:   8080,
			wantErr:    false,
		},
		{
			name:       "packet too small",
			packet:     []byte{0x00, 0x00, 0x00, 0x01, 1, 2, 3},
			wantOffset: 0,
			wantErr:    true,
		},
		{
			name: "fragmented packet",
			packet: []byte{
				0x00, 0x00, 0x01, // FRAG = 1
				0x01,
				1, 2, 3, 4,
				0x01, 0xBB,
			},
			wantOffset: 0,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offset, addr, err := parseSOCKS5UDPHeader(tt.packet)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseSOCKS5UDPHeader() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("parseSOCKS5UDPHeader() unexpected error: %v", err)
				return
			}

			if offset != tt.wantOffset {
				t.Errorf("parseSOCKS5UDPHeader() offset = %d, want %d", offset, tt.wantOffset)
			}

			udpAddr, ok := addr.(*net.UDPAddr)
			if !ok {
				t.Errorf("parseSOCKS5UDPHeader() addr type = %T, want *net.UDPAddr", addr)
				return
			}

			if !udpAddr.IP.Equal(tt.wantIP) {
				t.Errorf("parseSOCKS5UDPHeader() IP = %v, want %v", udpAddr.IP, tt.wantIP)
			}

			if udpAddr.Port != tt.wantPort {
				t.Errorf("parseSOCKS5UDPHeader() port = %d, want %d", udpAddr.Port, tt.wantPort)
			}
		})
	}
}

func TestParseSOCKS5UDPHeader_IPv6(t *testing.T) {
	tests := []struct {
		name       string
		packet     []byte
		wantOffset int
		wantIP     net.IP
		wantPort   int
		wantErr    bool
	}{
		{
			name: "valid IPv6",
			packet: []byte{
				0x00, 0x00, 0x00, // RSV + FRAG
				0x04,                                           // ATYP: IPv6
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // ::1
				0x01, 0xBB, // Port 443
				'D', 'a', 't', 'a', // Data
			},
			wantOffset: 22,
			wantIP:     net.ParseIP("::1"),
			wantPort:   443,
			wantErr:    false,
		},
		{
			name: "IPv6 packet too small",
			packet: []byte{
				0x00, 0x00, 0x00,
				0x04,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Missing last byte
			},
			wantOffset: 0,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offset, addr, err := parseSOCKS5UDPHeader(tt.packet)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseSOCKS5UDPHeader() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("parseSOCKS5UDPHeader() unexpected error: %v", err)
				return
			}

			if offset != tt.wantOffset {
				t.Errorf("parseSOCKS5UDPHeader() offset = %d, want %d", offset, tt.wantOffset)
			}

			udpAddr, ok := addr.(*net.UDPAddr)
			if !ok {
				t.Errorf("parseSOCKS5UDPHeader() addr type = %T, want *net.UDPAddr", addr)
				return
			}

			if !udpAddr.IP.Equal(tt.wantIP) {
				t.Errorf("parseSOCKS5UDPHeader() IP = %v, want %v", udpAddr.IP, tt.wantIP)
			}

			if udpAddr.Port != tt.wantPort {
				t.Errorf("parseSOCKS5UDPHeader() port = %d, want %d", udpAddr.Port, tt.wantPort)
			}
		})
	}
}

func TestParseSOCKS5UDPHeader_Domain(t *testing.T) {
	// Test domain address type (ATYP = 0x03)
	packet := []byte{
		0x00, 0x00, 0x00, // RSV + FRAG
		0x03, // ATYP: Domain
		11,   // Domain length
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		0x01, 0xBB, // Port 443
		'D', 'a', 't', 'a',
	}

	offset, addr, err := parseSOCKS5UDPHeader(packet)
	if err != nil {
		t.Fatalf("parseSOCKS5UDPHeader() unexpected error: %v", err)
	}

	// Offset should be 3 + 1 + 1 + 11 + 2 = 18
	expectedOffset := 18
	if offset != expectedOffset {
		t.Errorf("parseSOCKS5UDPHeader() offset = %d, want %d", offset, expectedOffset)
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("parseSOCKS5UDPHeader() addr type = %T, want *net.UDPAddr", addr)
	}

	if udpAddr.Port != 443 {
		t.Errorf("parseSOCKS5UDPHeader() port = %d, want 443", udpAddr.Port)
	}
}

func TestRoundTrip_HeaderBuildParse(t *testing.T) {
	// Test that building a header and parsing it back gives the same address
	addresses := []*net.UDPAddr{
		{IP: net.ParseIP("1.2.3.4"), Port: 443},
		{IP: net.ParseIP("192.168.1.1"), Port: 8080},
		{IP: net.ParseIP("::1"), Port: 443},
		{IP: net.ParseIP("2001:db8::1"), Port: 80},
		{IP: net.ParseIP("10.0.0.1"), Port: 65535},
	}

	testData := []byte("Hello, World!")

	for _, addr := range addresses {
		t.Run(addr.String(), func(t *testing.T) {
			// Build header
			header := buildSOCKS5UDPHeader(addr)

			// Combine with data
			packet := append(header, testData...)

			// Parse back
			offset, parsedAddr, err := parseSOCKS5UDPHeader(packet)
			if err != nil {
				t.Fatalf("parseSOCKS5UDPHeader() error: %v", err)
			}

			// Verify offset is correct (header length)
			if offset != len(header) {
				t.Errorf("offset = %d, want %d", offset, len(header))
			}

			// Verify address matches
			parsedUDP, ok := parsedAddr.(*net.UDPAddr)
			if !ok {
				t.Fatalf("parsed addr type = %T, want *net.UDPAddr", parsedAddr)
			}

			if !parsedUDP.IP.Equal(addr.IP) {
				t.Errorf("parsed IP = %v, want %v", parsedUDP.IP, addr.IP)
			}

			if parsedUDP.Port != addr.Port {
				t.Errorf("parsed port = %d, want %d", parsedUDP.Port, addr.Port)
			}

			// Verify data is intact
			data := packet[offset:]
			if !bytes.Equal(data, testData) {
				t.Errorf("data = %v, want %v", data, testData)
			}
		})
	}
}

func TestNewSOCKS5UDPConn(t *testing.T) {
	tests := []struct {
		name     string
		proxyURL string
		wantHost string
		wantPort string
		wantUser string
		wantPass string
		wantErr  bool
	}{
		{
			name:     "simple socks5",
			proxyURL: "socks5://localhost:1080",
			wantHost: "localhost",
			wantPort: "1080",
			wantErr:  false,
		},
		{
			name:     "socks5 with auth",
			proxyURL: "socks5://user:pass@proxy.example.com:1080",
			wantHost: "proxy.example.com",
			wantPort: "1080",
			wantUser: "user",
			wantPass: "pass",
			wantErr:  false,
		},
		{
			name:     "socks5h scheme",
			proxyURL: "socks5h://10.0.0.1:9050",
			wantHost: "10.0.0.1",
			wantPort: "9050",
			wantErr:  false,
		},
		{
			name:     "default port",
			proxyURL: "socks5://proxy.local",
			wantHost: "proxy.local",
			wantPort: "1080",
			wantErr:  false,
		},
		{
			name:     "http proxy rejected",
			proxyURL: "http://proxy:8080",
			wantErr:  true,
		},
		{
			name:     "https proxy rejected",
			proxyURL: "https://proxy:8080",
			wantErr:  true,
		},
		{
			name:     "invalid URL",
			proxyURL: "://invalid",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := NewSOCKS5UDPConn(tt.proxyURL)

			if tt.wantErr {
				if err == nil {
					t.Errorf("NewSOCKS5UDPConn() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("NewSOCKS5UDPConn() unexpected error: %v", err)
				return
			}

			if conn.proxyHost != tt.wantHost {
				t.Errorf("proxyHost = %q, want %q", conn.proxyHost, tt.wantHost)
			}

			if conn.proxyPort != tt.wantPort {
				t.Errorf("proxyPort = %q, want %q", conn.proxyPort, tt.wantPort)
			}

			if conn.username != tt.wantUser {
				t.Errorf("username = %q, want %q", conn.username, tt.wantUser)
			}

			if conn.password != tt.wantPass {
				t.Errorf("password = %q, want %q", conn.password, tt.wantPass)
			}
		})
	}
}

func TestSocks5ReplyString(t *testing.T) {
	tests := []struct {
		code byte
		want string
	}{
		{0x00, "success"},
		{0x01, "general SOCKS server failure"},
		{0x02, "connection not allowed by ruleset"},
		{0x03, "network unreachable"},
		{0x04, "host unreachable"},
		{0x05, "connection refused"},
		{0x06, "TTL expired"},
		{0x07, "command not supported"},
		{0x08, "address type not supported"},
		{0x99, "unknown error (code 153)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := socks5ReplyString(tt.code)
			if got != tt.want {
				t.Errorf("socks5ReplyString(%d) = %q, want %q", tt.code, got, tt.want)
			}
		})
	}
}

func BenchmarkBuildSOCKS5UDPHeader_IPv4(b *testing.B) {
	addr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 443}
	for i := 0; i < b.N; i++ {
		buildSOCKS5UDPHeader(addr)
	}
}

func BenchmarkBuildSOCKS5UDPHeader_IPv6(b *testing.B) {
	addr := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}
	for i := 0; i < b.N; i++ {
		buildSOCKS5UDPHeader(addr)
	}
}

func BenchmarkParseSOCKS5UDPHeader_IPv4(b *testing.B) {
	packet := []byte{
		0x00, 0x00, 0x00,
		0x01,
		1, 2, 3, 4,
		0x01, 0xBB,
		'H', 'e', 'l', 'l', 'o',
	}
	for i := 0; i < b.N; i++ {
		parseSOCKS5UDPHeader(packet)
	}
}

func BenchmarkParseSOCKS5UDPHeader_IPv6(b *testing.B) {
	packet := []byte{
		0x00, 0x00, 0x00,
		0x04,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		0x01, 0xBB,
		'H', 'e', 'l', 'l', 'o',
	}
	for i := 0; i < b.N; i++ {
		parseSOCKS5UDPHeader(packet)
	}
}
