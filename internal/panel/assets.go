package panel

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"strconv"
	"strings"
)

// staticAsset is one file /static/ serves, read once at start: its bytes, a
// gzip copy for text, and the version the page's links carry.
type staticAsset struct {
	contentType string
	body        []byte
	gz          []byte // nil: served as it is (fonts and images are compressed already)
	version     string // the first ten hex digits of the file's SHA-256
}

const (
	// staticMaxAge is for a request without the file's current ?v=, such as
	// the font the stylesheet names and the manifest's icons.
	staticMaxAge = "public, max-age=86400"
	// staticImmutable is for a request naming the file's current ?v=: those
	// bytes never change under that address.
	staticImmutable = "public, max-age=31536000, immutable"
)

// loadStaticAssets reads every served file. A file that cannot be read is
// left out (and answers 404); its version is "0".
func loadStaticAssets(files fs.FS) (map[string]*staticAsset, map[string]string) {
	assets := map[string]*staticAsset{}
	versions := map[string]string{}
	for _, f := range staticTypes {
		raw, err := fs.ReadFile(files, f.name)
		if err != nil {
			versions[f.name] = "0"
			continue
		}
		sum := sha256.Sum256(raw)
		a := &staticAsset{contentType: f.contentType, body: raw, version: hex.EncodeToString(sum[:])[:10]}
		if strings.HasPrefix(f.contentType, "text/") {
			a.gz = gzipBytes(raw)
		}
		assets[f.name] = a
		versions[f.name] = a.version
	}
	return assets, versions
}

func gzipBytes(raw []byte) []byte {
	var b bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&b, gzip.BestCompression)
	zw.Write(raw)
	zw.Close()
	return b.Bytes()
}

// acceptsGzip reads Accept-Encoding: gzip, x-gzip or *, with a q-value
// above zero, and no gzip;q=0.
func acceptsGzip(values []string) bool {
	accepted, refused := false, false
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			coding, params, _ := strings.Cut(item, ";")
			coding = strings.ToLower(strings.TrimSpace(coding))
			if coding != "gzip" && coding != "x-gzip" && coding != "*" {
				continue
			}
			weight := 1.0
			for _, p := range strings.Split(params, ";") {
				name, q, _ := strings.Cut(strings.TrimSpace(p), "=")
				if strings.EqualFold(strings.TrimSpace(name), "q") {
					parsed, err := strconv.ParseFloat(strings.TrimSpace(q), 64)
					if err != nil || parsed < 0 || parsed > 1 {
						parsed = 0
					}
					weight = parsed
				}
			}
			switch {
			case weight > 0:
				accepted = true
			case coding != "*":
				refused = true
			}
		}
	}
	return accepted && !refused
}

// etagMatches reads If-None-Match against one strong tag (weak comparison,
// as RFC 9110 asks for If-None-Match).
func etagMatches(values []string, etag string) bool {
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			item = strings.TrimPrefix(strings.TrimSpace(item), "W/")
			if item == "*" || item == etag {
				return true
			}
		}
	}
	return false
}
