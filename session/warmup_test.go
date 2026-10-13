package session

import (
	"context"
	"testing"

	"github.com/sardanioss/httpcloak/fingerprint"
)

func TestParseSubresources(t *testing.T) {
	html := []byte(`<!DOCTYPE html>
<html>
<head>
	<link rel="stylesheet" href="/css/main.css">
	<link rel="stylesheet" href="/css/theme.css">
	<link rel="icon" href="/favicon.ico">
	<link rel="preload" href="/fonts/roboto.woff2" as="font">
	<link rel="preload" href="/js/preloaded.js" as="script">
	<link rel="preload" href="/img/hero.webp" as="image">
	<link rel="preload" href="/css/critical.css" as="style">
	<script src="/js/analytics.js"></script>
	<script src="/js/app.js"></script>
</head>
<body>
	<img src="/img/logo.png">
	<img src="/img/banner.jpg">
	<script>console.log("inline")</script>
</body>
</html>`)

	resources := parseSubresources(html, "https://example.com/page")

	// Count by type
	counts := map[resourceType]int{}
	for _, r := range resources {
		counts[r.typ]++
	}

	if counts[resourceCSS] != 3 { // main.css, theme.css, critical.css (preload as=style)
		t.Errorf("expected 3 CSS resources, got %d", counts[resourceCSS])
	}
	if counts[resourceJS] != 3 { // preloaded.js, analytics.js, app.js
		t.Errorf("expected 3 JS resources, got %d", counts[resourceJS])
	}
	if counts[resourceImage] != 4 { // favicon.ico (icon), hero.webp (preload as=image), logo.png, banner.jpg
		t.Errorf("expected 4 Image resources, got %d", counts[resourceImage])
	}
	if counts[resourceFont] != 1 { // roboto.woff2
		t.Errorf("expected 1 Font resource, got %d", counts[resourceFont])
	}
}

func TestParseSubresources_Correct(t *testing.T) {
	html := []byte(`<!DOCTYPE html>
<html>
<head>
	<link rel="stylesheet" href="/css/main.css">
	<link rel="icon" href="/favicon.ico">
	<link rel="preload" href="/fonts/roboto.woff2" as="font">
	<script src="/js/app.js"></script>
</head>
<body>
	<img src="/img/logo.png">
</body>
</html>`)

	resources := parseSubresources(html, "https://example.com")

	expected := []struct {
		url string
		typ resourceType
	}{
		{"https://example.com/css/main.css", resourceCSS},
		{"https://example.com/favicon.ico", resourceImage},
		{"https://example.com/fonts/roboto.woff2", resourceFont},
		{"https://example.com/js/app.js", resourceJS},
		{"https://example.com/img/logo.png", resourceImage},
	}

	if len(resources) != len(expected) {
		t.Fatalf("expected %d resources, got %d: %+v", len(expected), len(resources), resources)
	}

	for i, exp := range expected {
		if resources[i].url != exp.url {
			t.Errorf("resource[%d] url = %q, want %q", i, resources[i].url, exp.url)
		}
		if resources[i].typ != exp.typ {
			t.Errorf("resource[%d] type = %d, want %d", i, resources[i].typ, exp.typ)
		}
	}
}

func TestParseSubresources_Dedup(t *testing.T) {
	html := []byte(`<html>
<head>
	<link rel="stylesheet" href="/css/main.css">
	<link rel="stylesheet" href="/css/main.css">
</head>
<body>
	<img src="/logo.png">
	<img src="/logo.png">
</body>
</html>`)

	resources := parseSubresources(html, "https://example.com")
	if len(resources) != 2 {
		t.Errorf("expected 2 deduplicated resources, got %d", len(resources))
	}
}

func TestParseSubresources_Cap(t *testing.T) {
	// Build HTML with 60 images — should be capped at 50
	var b []byte
	b = append(b, "<html><body>"...)
	for i := 0; i < 60; i++ {
		b = append(b, []byte("<img src=\"/img/"+string(rune('a'+i%26))+string(rune('0'+i/26))+".png\">")...)
	}
	b = append(b, "</body></html>"...)

	resources := parseSubresources(b, "https://example.com")
	if len(resources) > maxSubresources {
		t.Errorf("expected at most %d resources, got %d", maxSubresources, len(resources))
	}
}

func TestParseSubresources_RelativeURLs(t *testing.T) {
	html := []byte(`<html>
<head>
	<link rel="stylesheet" href="css/style.css">
	<script src="js/app.js"></script>
</head>
<body>
	<img src="//cdn.example.com/logo.png">
	<img src="https://other.com/img.jpg">
</body>
</html>`)

	resources := parseSubresources(html, "https://example.com/pages/index.html")

	urls := make(map[string]bool)
	for _, r := range resources {
		urls[r.url] = true
	}

	want := []string{
		"https://example.com/pages/css/style.css",
		"https://example.com/pages/js/app.js",
		"https://cdn.example.com/logo.png",
		"https://other.com/img.jpg",
	}
	for _, u := range want {
		if !urls[u] {
			t.Errorf("missing expected URL %q; got URLs: %v", u, urls)
		}
	}
}

func TestParseSubresources_NoResources(t *testing.T) {
	html := []byte(`<html><body><p>No resources here</p></body></html>`)
	resources := parseSubresources(html, "https://example.com")
	if len(resources) != 0 {
		t.Errorf("expected 0 resources, got %d", len(resources))
	}
}

func TestGroupByPriority(t *testing.T) {
	resources := []subresource{
		{url: "/a.css", typ: resourceCSS},
		{url: "/b.js", typ: resourceJS},
		{url: "/c.png", typ: resourceImage},
		{url: "/d.woff2", typ: resourceFont},
		{url: "/e.css", typ: resourceCSS},
		{url: "/f.jpg", typ: resourceImage},
	}

	cssAndFonts, scripts, images := groupByPriority(resources)

	if len(cssAndFonts) != 3 { // 2 CSS + 1 font
		t.Errorf("cssAndFonts: expected 3, got %d", len(cssAndFonts))
	}
	if len(scripts) != 1 {
		t.Errorf("scripts: expected 1, got %d", len(scripts))
	}
	if len(images) != 2 {
		t.Errorf("images: expected 2, got %d", len(images))
	}

	// Verify CSS and fonts are in cssAndFonts
	for _, r := range cssAndFonts {
		if r.typ != resourceCSS && r.typ != resourceFont {
			t.Errorf("cssAndFonts contains unexpected type %d", r.typ)
		}
	}
}

func TestGroupByPriority_Empty(t *testing.T) {
	cssAndFonts, scripts, images := groupByPriority(nil)
	if cssAndFonts != nil || scripts != nil || images != nil {
		t.Error("expected nil slices for empty input")
	}
}

func TestBuildSubresourceHeaders_CSS(t *testing.T) {
	headers := buildSubresourceHeaders(nil, resourceCSS, "https://example.com/page", "https://example.com/style.css")

	assertHeader(t, headers, "Accept", "text/css,*/*;q=0.1")
	assertHeader(t, headers, "Sec-Fetch-Mode", "no-cors")
	assertHeader(t, headers, "Sec-Fetch-Dest", "style")
	assertHeader(t, headers, "Referer", "https://example.com/page")
	assertHeader(t, headers, "Priority", "u=0, i")
	assertHeader(t, headers, "Sec-Fetch-Site", "same-origin")
}

func TestBuildSubresourceHeaders_JS(t *testing.T) {
	headers := buildSubresourceHeaders(nil, resourceJS, "https://example.com/page", "https://example.com/app.js")

	assertHeader(t, headers, "Accept", "*/*")
	assertHeader(t, headers, "Sec-Fetch-Mode", "no-cors")
	assertHeader(t, headers, "Sec-Fetch-Dest", "script")
	assertHeader(t, headers, "Priority", "u=1")
}

func TestBuildSubresourceHeaders_Image(t *testing.T) {
	headers := buildSubresourceHeaders(nil, resourceImage, "https://example.com/page", "https://example.com/logo.png")

	assertHeader(t, headers, "Accept", "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8")
	assertHeader(t, headers, "Sec-Fetch-Mode", "no-cors")
	assertHeader(t, headers, "Sec-Fetch-Dest", "image")
	assertHeader(t, headers, "Priority", "u=2")
}

func TestBuildSubresourceHeaders_Font(t *testing.T) {
	headers := buildSubresourceHeaders(nil, resourceFont, "https://example.com/page", "https://example.com/font.woff2")

	assertHeader(t, headers, "Accept", "*/*")
	assertHeader(t, headers, "Sec-Fetch-Mode", "cors")
	assertHeader(t, headers, "Sec-Fetch-Dest", "font")
	assertHeader(t, headers, "Priority", "u=3")
}

func TestBuildSubresourceHeaders_CrossSite(t *testing.T) {
	headers := buildSubresourceHeaders(nil, resourceImage, "https://example.com/page", "https://cdn.other.com/img.png")
	assertHeader(t, headers, "Sec-Fetch-Site", "cross-site")
}

func TestBuildSubresourceHeaders_SameSite(t *testing.T) {
	headers := buildSubresourceHeaders(nil, resourceCSS, "https://www.example.com/page", "https://cdn.example.com/style.css")
	assertHeader(t, headers, "Sec-Fetch-Site", "same-site")
}

func TestFontContext(t *testing.T) {
	ctx := fingerprint.FontContext("https://example.com/page", "https://example.com/font.woff2")
	if ctx.Mode != fingerprint.FetchModeCORS {
		t.Errorf("FontContext mode = %q, want %q", ctx.Mode, fingerprint.FetchModeCORS)
	}
	if ctx.Dest != fingerprint.FetchDestFont {
		t.Errorf("FontContext dest = %q, want %q", ctx.Dest, fingerprint.FetchDestFont)
	}
	if ctx.IsUserTriggered {
		t.Error("FontContext should not be user-triggered")
	}
}

func TestInterBatchDelay_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := interBatchDelay(ctx, 1000, 2000)
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestInterBatchDelay_ZeroDelay(t *testing.T) {
	err := interBatchDelay(context.Background(), 0, 0)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func assertHeader(t *testing.T, headers map[string][]string, key, want string) {
	t.Helper()
	vals, ok := headers[key]
	if !ok || len(vals) == 0 {
		t.Errorf("header %q not found", key)
		return
	}
	if vals[0] != want {
		t.Errorf("header %q = %q, want %q", key, vals[0], want)
	}
}

// A preset with a priority table gets its own browser's priority header on
// warmup subresources rather than the fallback constants, which matched no
// browser (Chrome sends u=0 on a stylesheet, u=2, i on an image).
func TestBuildSubresourceHeadersUsesThePresetsPriorityTable(t *testing.T) {
	cases := []struct {
		preset string
		typ    resourceType
		want   string
	}{
		{"chrome-155-windows", resourceCSS, "u=0"},
		{"chrome-155-windows", resourceImage, "u=2, i"},
		{"chrome-155-windows", resourceJS, "u=1"},
		{"firefox-148-windows", resourceCSS, "u=2"},
		{"firefox-148-windows", resourceImage, "u=5, i"},
		{"firefox-148-windows", resourceFont, ""},
	}
	for _, tc := range cases {
		p := fingerprint.Get(tc.preset)
		h := buildSubresourceHeaders(p, tc.typ, "https://example.com/", "https://example.com/x")
		got := ""
		if v := h["Priority"]; len(v) > 0 {
			got = v[0]
		}
		if got != tc.want {
			t.Errorf("%s type %d: priority %q, want %q", tc.preset, tc.typ, got, tc.want)
		}
	}
}
