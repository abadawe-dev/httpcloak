package session

import (
	"context"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/sardanioss/httpcloak/fingerprint"
	"github.com/sardanioss/httpcloak/transport"
	"golang.org/x/net/html"
)

// resourceType classifies a discovered subresource.
type resourceType int

const (
	resourceCSS   resourceType = iota
	resourceJS
	resourceImage
	resourceFont
)

// subresource is a URL discovered in the HTML with its type.
type subresource struct {
	url  string
	typ  resourceType
}

// maxSubresources caps how many subresources we fetch.
const maxSubresources = 50

// concurrencyLimit matches Chrome's per-host H1 connection limit.
const concurrencyLimit = 6

// Warmup simulates a real browser page load: fetches the HTML, discovers
// subresources (CSS, JS, images, fonts), and fetches them in batches with
// realistic timing. Cookies, TLS sessions, cache state, and client hints
// all accumulate through the existing Request() pipeline.
//
// Navigation failure returns an error. Subresource failures are silently
// ignored (matching browser behavior). A non-HTML response returns nil
// (the navigation still warmed TLS/cookies).
func (s *Session) Warmup(ctx context.Context, url string) error {
	// 1. Navigation request — preset headers apply automatically
	resp, err := s.Request(ctx, &transport.Request{
		Method: "GET",
		URL:    url,
	})
	if err != nil {
		return err
	}

	// Read body for HTML parsing
	body, err := resp.Bytes()
	if err != nil {
		return err
	}

	// Non-HTML response — still warmed TLS/cookies, return success
	ct := ""
	if vals, ok := resp.Headers["content-type"]; ok && len(vals) > 0 {
		ct = vals[0]
	}
	if !strings.Contains(ct, "text/html") {
		return nil
	}

	// 2. Parse HTML and extract subresource URLs
	resources := parseSubresources(body, url)

	// 3. Group by priority: [CSS+Fonts] → [JS] → [Images]
	cssAndFonts, scripts, images := groupByPriority(resources)

	// 4. Fetch batches with inter-batch delays
	pageURL := resp.FinalURL
	if pageURL == "" {
		pageURL = url
	}

	batches := [][]subresource{cssAndFonts, scripts, images}
	delays := []struct{ min, max int }{{0, 0}, {50, 150}, {100, 300}}

	for i, batch := range batches {
		if len(batch) == 0 {
			continue
		}

		// Check context before each batch
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Inter-batch delay (skip for first batch)
		if i > 0 && delays[i].max > 0 {
			if err := interBatchDelay(ctx, delays[i].min, delays[i].max); err != nil {
				return err
			}
		}

		fetchBatch(ctx, s, batch, pageURL)
	}

	return nil
}

// parseSubresources tokenizes HTML and extracts subresource URLs.
func parseSubresources(body []byte, baseURL string) []subresource {
	tokenizer := html.NewTokenizer(strings.NewReader(string(body)))
	seen := make(map[string]bool)
	var resources []subresource

	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}

		tn, hasAttr := tokenizer.TagName()
		if !hasAttr {
			continue
		}
		tagName := string(tn)

		switch tagName {
		case "link":
			href, rel, as := parseLinkAttrs(tokenizer)
			if href == "" {
				continue
			}
			var typ resourceType
			var matched bool
			switch rel {
			case "stylesheet":
				typ = resourceCSS
				matched = true
			case "icon":
				typ = resourceImage
				matched = true
			case "preload":
				matched = true
				switch as {
				case "style":
					typ = resourceCSS
				case "script":
					typ = resourceJS
				case "image":
					typ = resourceImage
				case "font":
					typ = resourceFont
				default:
					matched = false
				}
			}
			if matched {
				resolved := resolveURL(baseURL, href)
				if !seen[resolved] {
					seen[resolved] = true
					resources = append(resources, subresource{url: resolved, typ: typ})
				}
			}

		case "script":
			src := getAttr(tokenizer, "src")
			if src != "" {
				resolved := resolveURL(baseURL, src)
				if !seen[resolved] {
					seen[resolved] = true
					resources = append(resources, subresource{url: resolved, typ: resourceJS})
				}
			}

		case "img":
			src := getAttr(tokenizer, "src")
			if src != "" {
				resolved := resolveURL(baseURL, src)
				if !seen[resolved] {
					seen[resolved] = true
					resources = append(resources, subresource{url: resolved, typ: resourceImage})
				}
			}
		}

		if len(resources) >= maxSubresources {
			break
		}
	}

	return resources
}

// parseLinkAttrs extracts href, rel, and as attributes from a <link> tag.
func parseLinkAttrs(z *html.Tokenizer) (href, rel, as string) {
	for {
		key, val, more := z.TagAttr()
		k := string(key)
		switch k {
		case "href":
			href = string(val)
		case "rel":
			rel = strings.ToLower(string(val))
		case "as":
			as = strings.ToLower(string(val))
		}
		if !more {
			break
		}
	}
	return
}

// getAttr extracts a single attribute value from the current tag's remaining attributes.
func getAttr(z *html.Tokenizer, name string) string {
	for {
		key, val, more := z.TagAttr()
		if string(key) == name {
			return string(val)
		}
		if !more {
			break
		}
	}
	return ""
}

// groupByPriority splits resources into three batches matching Chrome's loading order.
func groupByPriority(resources []subresource) (cssAndFonts, scripts, images []subresource) {
	for _, r := range resources {
		switch r.typ {
		case resourceCSS, resourceFont:
			cssAndFonts = append(cssAndFonts, r)
		case resourceJS:
			scripts = append(scripts, r)
		case resourceImage:
			images = append(images, r)
		}
	}
	return
}

// fetchBatch fetches a batch of subresources concurrently (up to concurrencyLimit).
// Errors are silently ignored (matches browser behavior).
func fetchBatch(ctx context.Context, s *Session, batch []subresource, pageURL string) {
	var preset *fingerprint.Preset
	if s.Config != nil && s.Config.Preset != "" {
		preset = fingerprint.Get(s.Config.Preset)
	}
	sem := make(chan struct{}, concurrencyLimit)
	var wg sync.WaitGroup

	for _, res := range batch {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		sem <- struct{}{} // acquire

		go func(r subresource) {
			defer wg.Done()
			defer func() { <-sem }() // release

			if ctx.Err() != nil {
				return
			}

			headers := buildSubresourceHeaders(preset, r.typ, pageURL, r.url)
			req := &transport.Request{
				Method:  "GET",
				URL:     r.url,
				Headers: headers,
			}

			resp, err := s.Request(ctx, req)
			if err != nil {
				return
			}
			// Discard body — side effects (cookies/cache/TLS) already captured
			if resp.Body != nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}(res)
	}

	// Context-aware wait
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// buildSubresourceHeaders returns the headers for a subresource request,
// overriding the preset's navigation defaults with per-type values.
func buildSubresourceHeaders(preset *fingerprint.Preset, typ resourceType, pageURL, targetURL string) map[string][]string {
	var reqCtx fingerprint.RequestContext
	var accept, priority string

	switch typ {
	case resourceCSS:
		reqCtx = fingerprint.StyleContext(pageURL, targetURL)
		accept = "text/css,*/*;q=0.1"
		priority = "u=0, i"
	case resourceJS:
		reqCtx = fingerprint.ScriptContext(pageURL, targetURL)
		accept = "*/*"
		priority = "u=1"
	case resourceImage:
		reqCtx = fingerprint.ImageContext(pageURL, targetURL)
		accept = preset.ResolveImageAccept()
		priority = "u=2"
	case resourceFont:
		reqCtx = fingerprint.FontContext(pageURL, targetURL)
		accept = "*/*"
		priority = "u=3"
	}

	secFetch := fingerprint.GenerateSecFetchHeaders(reqCtx)

	// The constants above are only a fallback for presets without a priority
	// table (Safari and iOS, never measured here). Every other preset sends
	// what its browser sends for the dest; the transport would apply the same
	// table again, so this keeps the two layers from disagreeing.
	if preset != nil {
		if _, _, hv, ok := preset.H2PriorityFor(secFetch.Dest); ok {
			priority = hv
		}
	}

	headers := map[string][]string{
		"Accept":         {accept},
		"Sec-Fetch-Site": {secFetch.Site},
		"Sec-Fetch-Mode": {secFetch.Mode},
		"Sec-Fetch-Dest": {secFetch.Dest},
		"Referer":        {pageURL},
	}
	if priority != "" {
		headers["Priority"] = []string{priority}
	}

	return headers
}

// interBatchDelay waits a random duration between min and max milliseconds,
// respecting context cancellation.
func interBatchDelay(ctx context.Context, minMs, maxMs int) error {
	d := time.Duration(minMs) * time.Millisecond
	if maxMs > minMs {
		d += time.Duration(randInt64(int64(maxMs-minMs))) * time.Millisecond
	}
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
