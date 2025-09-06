package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

type CacheEntry struct {
	Path     string    `json:"path"`
	MD5      string    `json:"md5"`
	ModTime  time.Time `json:"mod_time"`
	Size     int64     `json:"size"`
	LastUsed time.Time `json:"last_used"`
}

type MD5Cache struct {
	mu      sync.RWMutex
	entries map[string]*CacheEntry
	hits    int
	misses  int
}

func NewMD5Cache() *MD5Cache {
	return &MD5Cache{
		entries: make(map[string]*CacheEntry),
	}
}

func (c *MD5Cache) loadFromFile(filename string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	var entries map[string]*CacheEntry
	if err := json.NewDecoder(file).Decode(&entries); err != nil {
		return err
	}

	c.entries = entries
	return nil
}

func (c *MD5Cache) saveToFile(filename string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	os.MkdirAll(filepath.Dir(filename), 0755)

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewEncoder(file).Encode(c.entries)
}

func (c *MD5Cache) get(path string, modTime time.Time, size int64) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.entries[path]
	if !exists {
		c.misses++
		return "", false
	}

	if entry.ModTime != modTime || entry.Size != size {
		delete(c.entries, path)
		c.misses++
		return "", false
	}

	entry.LastUsed = time.Now()
	c.hits++
	return entry.MD5, true
}

func (c *MD5Cache) set(path string, md5Hash string, modTime time.Time, size int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= 100000 {
		oldestTime := time.Now()
		var oldestPath string
		for p, e := range c.entries {
			if e.LastUsed.Before(oldestTime) {
				oldestTime = e.LastUsed
				oldestPath = p
			}
		}
		if oldestPath != "" {
			delete(c.entries, oldestPath)
		}
	}

	c.entries[path] = &CacheEntry{
		Path:     path,
		MD5:      md5Hash,
		ModTime:  modTime,
		Size:     size,
		LastUsed: time.Now(),
	}
}

func (c *MD5Cache) getStats() (int, int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hits, c.misses
}

func calculateMD5(filename string, cache *MD5Cache) (string, error) {
	stat, err := os.Stat(filename)
	if err != nil {
		return "", err
	}

	if cachedMD5, found := cache.get(filename, stat.ModTime(), stat.Size()); found {
		return cachedMD5, nil
	}

	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	md5Hash := hex.EncodeToString(hash.Sum(nil))
	cache.set(filename, md5Hash, stat.ModTime(), stat.Size())

	return md5Hash, nil
}

func convertBlobNameToLocalPath(blobName string) string {
	if strings.HasPrefix(blobName, "p") || strings.HasPrefix(blobName, "q") || strings.HasPrefix(blobName, "s") {
		return filepath.Join("/var/kopia/repository", blobName[:1], blobName)
	}

	if strings.HasPrefix(blobName, "xw") {
		return filepath.Join("/var/kopia/repository", blobName)
	}

	if strings.HasPrefix(blobName, "xn0") {
		return filepath.Join("/var/kopia/repository", blobName)
	}

	if strings.HasSuffix(blobName, ".f") && strings.HasPrefix(blobName, "_log") {
		return filepath.Join("/var/kopia/repository", blobName)
	}

	return filepath.Join("/var/kopia/repository", blobName)
}

func main() {
	ctx := context.Background()

	client, err := storage.NewClient(ctx)
	if err != nil {
		panic(fmt.Sprintf("Failed to create client: %v", err))
	}
	defer client.Close()

	cache := NewMD5Cache()
	cacheFile := "/var/kopia/.cache/kopia_md5_cache.json"
	if err := cache.loadFromFile(cacheFile); err != nil {
		fmt.Printf("Warning: Could not load cache: %v\n", err)
	}

	bucket := client.Bucket("kopia-iowa")

	query := &storage.Query{
		Projection: storage.ProjectionNoACL,
	}

	var gcsBlobs []struct {
		Name string
		MD5  []byte
		Size int64
	}

	it := bucket.Objects(ctx, query)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			panic(fmt.Sprintf("Failed to iterate: %v", err))
		}

		gcsBlobs = append(gcsBlobs, struct {
			Name string
			MD5  []byte
			Size int64
		}{
			Name: attrs.Name,
			MD5:  attrs.MD5,
			Size: attrs.Size,
		})
	}

	fmt.Printf("Found %d blobs in GCS\n", len(gcsBlobs))

	var matched, errors int

	for i, gcsBlob := range gcsBlobs {
		if i > 0 && i%100 == 0 {
			fmt.Printf("Progress: %d/%d blobs processed\n", i, len(gcsBlobs))
		}

		localPath := convertBlobNameToLocalPath(gcsBlob.Name)

		localMD5, err := calculateMD5(localPath, cache)
		if err != nil {
			fmt.Printf("Error calculating local MD5 for %s: %v\n", localPath, err)
			errors++
			continue
		}

		gcsMD5 := hex.EncodeToString(gcsBlob.MD5)

		if localMD5 == gcsMD5 {
			matched++
		} else {
			fmt.Printf("MISMATCH: %s\n", gcsBlob.Name)
			fmt.Printf("  Local:  %s\n", localMD5)
			fmt.Printf("  GCS:    %s\n", gcsMD5)
			errors++
		}
	}

	if err := cache.saveToFile(cacheFile); err != nil {
		fmt.Printf("Warning: Could not save cache: %v\n", err)
	}

	hits, misses := cache.getStats()
	fmt.Printf("\nVerification Results:\n")
	fmt.Printf("  Matched: %d/%d blobs\n", matched, len(gcsBlobs))
	if errors > 0 {
		fmt.Printf("  Errors: %d\n", errors)
	}
	fmt.Printf("  Cache: %d hits, %d misses\n", hits, misses)

	if matched == len(gcsBlobs) && errors == 0 {
		fmt.Printf("✓ Perfect verification: All blobs match!\n")
	} else {
		fmt.Printf("✗ Verification failed: %d mismatches/errors\n", errors)
	}
}