package providers

// The large-catalogue memory measurement (molebridge#79): heap during a
// NordVPN refresh as the exit runs it, for synthetic server lists from
// today's size up to what NordMaxCatalogBytes admits. Run it on its own, one
// size per process so the figures don't mix:
//
//	go test ./internal/providers -run '^$' -bench BenchmarkNordLargeCatalog -benchtime 1x
//
// It reports, per phase, the peak live heap (sampled every 50 µs, so a
// shorter spike can be missed), the bytes allocated, and the heap the result
// keeps once collected. The body is counted: the exit holds the download in
// one buffer while it parses.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// largeNordBody is a NordVPN list with n servers built from the fixture's
// first server, each with its own id, hostname, address and key, and padded
// with specification rows the parser ignores to about 1.5 KB a server, the
// live list's size (about 8 MB for 5,300 servers in November 2026).
func largeNordBody(tb testing.TB, n int) []byte {
	tb.Helper()
	doc := nordData(tb)
	template := obj(list(doc["servers"])[0])
	servers := make([]any, n)
	for i := range servers {
		s := obj(clone(tb, template))
		id := int64(1000000 + i)
		s["id"] = id
		s["hostname"] = fmt.Sprintf("us%d.nordvpn.com", 10000+i)
		s["name"] = fmt.Sprintf("United States #%d", 10000+i)
		// Documentation addresses repeat every 254 servers; nothing
		// requires them to be unique.
		addr := fmt.Sprintf("198.51.100.%d", i%254+1)
		s["station"] = addr
		specs := list(s["specifications"])
		for j := 0; j < 4; j++ {
			specs = append(specs, map[string]any{"id": int64(100 + j), "title": "Padding", "identifier": fmt.Sprintf("padding_%d", j),
				"values": []any{map[string]any{"id": int64(1000 + j), "value": fmt.Sprintf("%0100d", i)}}})
		}
		s["specifications"] = specs
		ips := list(s["ips"])
		for _, entry := range ips {
			e := obj(entry)
			e["server_id"] = id
			obj(e["ip"])["ip"] = addr
		}
		for _, tech := range list(s["technologies"]) {
			metadata, _ := obj(tech)["metadata"].([]any)
			for _, meta := range metadata {
				if m := obj(meta); m["name"] == "public_key" {
					m["value"] = fmt.Sprintf("%042dA=", i)
				}
			}
		}
		servers[i] = s
	}
	doc["servers"] = servers
	raw, err := json.Marshal(doc)
	if err != nil {
		tb.Fatal(err)
	}
	return raw
}

// heapPeak samples the live heap until stop is called and returns the
// highest figure.
func heapPeak() (stop func() uint64) {
	sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	var peak atomic.Uint64
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			metrics.Read(sample)
			if v := sample[0].Value.Uint64(); v > peak.Load() {
				peak.Store(v)
			}
			select {
			case <-done:
				return
			case <-time.After(50 * time.Microsecond):
			}
		}
	}()
	return func() uint64 {
		close(done)
		wg.Wait()
		return peak.Load()
	}
}

func liveHeap() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

func totalAlloc() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.TotalAlloc
}

const mib = 1 << 20

func BenchmarkNordLargeCatalog(b *testing.B) {
	for _, n := range []int{5300, 10600, 19000} {
		b.Run(fmt.Sprintf("servers=%d", n), func(b *testing.B) {
			body := largeNordBody(b, n)
			if int64(len(body)) > NordMaxCatalogBytes {
				b.Skipf("%d servers are %d bytes, over the download cap", n, len(body))
			}
			path := filepath.Join(b.TempDir(), "relays.json")
			for i := 0; i < b.N; i++ {
				// Parse: the body is a fresh buffer, as a download is.
				download := append([]byte(nil), body...)
				base := liveHeap()
				before := totalAlloc()
				stop := heapPeak()
				entries, err := ParseNordCatalogBody(download, false)
				peak := stop()
				if err != nil {
					b.Fatal(err)
				}
				allocated := totalAlloc() - before
				download = nil
				kept := liveHeap() - base + uint64(len(body)) // base held the body
				_ = download
				b.ReportMetric(float64(len(body))/mib, "body-MiB")
				b.ReportMetric(float64(entries.Len()), "servers-kept")
				b.ReportMetric(float64(peak-base+uint64(len(body)))/mib, "parse-peak-MiB")
				b.ReportMetric(float64(allocated)/mib, "parse-alloc-MiB")
				b.ReportMetric(float64(kept)/mib, "entries-MiB")

				// Publish: the snapshot written as relays.json.
				catalog := NewRelayCatalogFiles(path, path+".err", "nordvpn", false, time.Now)
				base = liveHeap()
				stop = heapPeak()
				if err := catalog.Publish(entries, nil); err != nil {
					b.Fatal(err)
				}
				peak = stop()
				info, err := os.Stat(path)
				if err != nil {
					b.Fatal(err)
				}
				b.ReportMetric(float64(info.Size())/mib, "snapshot-MiB")
				b.ReportMetric(float64(peak-base)/mib, "publish-peak-MiB")

				// Restart: the snapshot read back.
				entries, catalog = nil, nil
				base = liveHeap()
				stop = heapPeak()
				again := NewRelayCatalogFiles(path, path+".err", "nordvpn", false, time.Now)
				peak = stop()
				if again.Relays.Len() != n {
					b.Fatalf("read back %d servers of %d", again.Relays.Len(), n)
				}
				b.ReportMetric(float64(peak-base)/mib, "reread-peak-MiB")
				runtime.KeepAlive(again)
			}
		})
	}
}
