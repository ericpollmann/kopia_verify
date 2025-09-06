package main

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

type CacheEntry struct {
	Path    string
	MD5     string
	ModTime int64
	Size    int64
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

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}

	for _, record := range records {
		if len(record) != 4 {
			continue
		}
		modTime, err := strconv.ParseInt(record[2], 10, 64)
		if err != nil {
			continue
		}
		size, err := strconv.ParseInt(record[3], 10, 64)
		if err != nil {
			continue
		}
		c.entries[record[0]] = &CacheEntry{
			Path:    record[0],
			MD5:     record[1],
			ModTime: modTime,
			Size:    size,
		}
	}
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

	writer := csv.NewWriter(file)
	defer writer.Flush()

	for _, entry := range c.entries {
		record := []string{
			entry.Path,
			entry.MD5,
			strconv.FormatInt(entry.ModTime, 10),
			strconv.FormatInt(entry.Size, 10),
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}
	return nil
}

func (c *MD5Cache) get(path string, modTime int64, size int64) (string, bool) {
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

	c.hits++
	return entry.MD5, true
}

func (c *MD5Cache) set(path string, md5Hash string, modTime int64, size int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= 100000 {
		for p := range c.entries {
			delete(c.entries, p)
			break
		}
	}

	c.entries[path] = &CacheEntry{
		Path:    path,
		MD5:     md5Hash,
		ModTime: modTime,
		Size:    size,
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

	modTimeMs := stat.ModTime().Unix() * 1000
	if cachedMD5, found := cache.get(filename, modTimeMs, stat.Size()); found {
		// Decode from base64 and return as hex
		md5Bytes, err := base64.StdEncoding.DecodeString(cachedMD5)
		if err == nil {
			return hex.EncodeToString(md5Bytes), nil
		}
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

	md5Bytes := hash.Sum(nil)
	md5Hex := hex.EncodeToString(md5Bytes)
	md5Base64 := base64.StdEncoding.EncodeToString(md5Bytes)
	cache.set(filename, md5Base64, modTimeMs, stat.Size())

	return md5Hex, nil
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
	cacheFile := "/var/kopia/.cache/kopia_md5_cache.csv"
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
