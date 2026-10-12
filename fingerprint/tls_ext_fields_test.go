package fingerprint

import (
	"strings"
	"testing"
)

// alpn, cert_compression, record_size_limit and permute_extensions are only
// read when the same tls block declares ja3 (and permute_extensions also on the
// raw path). Everywhere else they used to load cleanly and do nothing, so a
// preset could advertise a fingerprint it did not have (#130). Each of those
// shapes must now fail at load time, and the shapes that do apply must load.
func TestTLSExtensionFieldsAreNeverSilentlyDropped(t *testing.T) {
	const ja3 = "771,4865-4866-4867,0-10-11-13-16-43-45-51,29-23-24,0"
	for _, tc := range []struct {
		name, tls string
		wantErr   bool
	}{
		{"based_on + alpn", `"alpn": ["h2"]`, true},
		{"based_on + cert_compression", `"cert_compression": ["brotli"]`, true},
		{"based_on + record_size_limit", `"record_size_limit": 16385`, true},
		{"based_on + permute_extensions", `"permute_extensions": true`, true},
		{"client_hello + alpn", `"client_hello": "chrome-146-windows", "alpn": ["h2"]`, true},
		{"ja3 + alpn", `"ja3": "` + ja3 + `", "alpn": ["h2"]`, false},
		{"ja3 + permute_extensions", `"ja3": "` + ja3 + `", "permute_extensions": true`, false},
		{"based_on + signature_algorithms", `"signature_algorithms": [1027]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := "ext-fields-" + strings.NewReplacer(" ", "-", "+", "").Replace(tc.name)
			js := `{"version":1,"preset":{"name":"` + name + `","based_on":"chrome-146-windows","tls":{` + tc.tls + `}}}`
			_, err := LoadAndBuildPresetFromJSON([]byte(js))
			if tc.wantErr && err == nil {
				t.Fatalf("loaded without error; the field would have been silently ignored")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("rejected a shape that applies: %v", err)
			}
		})
	}
}
