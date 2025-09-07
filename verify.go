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
	// Handle special cases first
	
	// Log files: _log* -> /var/kopia/repository/_/log/{without_log_prefix}.f
	if strings.HasPrefix(blobName, "_log_") {
		actualName := strings.TrimPrefix(blobName, "_log") + ".f"
		return filepath.Join("/var/kopia/repository", "_", "log", actualName)
	}

	// Kopia config files: kopia.* -> /var/kopia/repository/kopia.*.f
	if strings.HasPrefix(blobName, "kopia.") {
		return filepath.Join("/var/kopia/repository", blobName + ".f")
	}

	// xw files: xw* -> /var/kopia/repository/xw*.f
	if strings.HasPrefix(blobName, "xw") {
		return filepath.Join("/var/kopia/repository", blobName + ".f")
	}

	// Standard blob pattern for ALL other prefixes: {first_char}/{next_3_chars}/{rest}.f
	if len(blobName) >= 4 {
		firstChar := blobName[:1]          // "p", "q", "s", "x", etc.
		next3Chars := blobName[1:4]        // "010", "n0_", etc.
		rest := blobName[4:] + ".f"        // remaining part + .f suffix
		return filepath.Join("/var/kopia/repository", firstChar, next3Chars, rest)
	}

	// Fallback for unknown patterns
	return filepath.Join("/var/kopia/repository", blobName)
}

func convertLocalPathToBlobName(localPath string) (string, error) {
	// Remove the repository prefix
	relPath := strings.TrimPrefix(localPath, "/var/kopia/repository/")
	
	// Handle special cases first
	
	// Log files: _/log/_20250903....f -> _log_20250903...
	if strings.HasPrefix(relPath, "_/log/_") {
		filename := strings.TrimPrefix(relPath, "_/log/")
		if strings.HasSuffix(filename, ".f") {
			return "_log" + strings.TrimSuffix(filename, ".f"), nil
		}
	}
	
	// Config files: kopia.repository.f -> kopia.repository
	if strings.HasPrefix(relPath, "kopia.") && strings.HasSuffix(relPath, ".f") {
		return strings.TrimSuffix(relPath, ".f"), nil
	}
	
	// xw files: xw1757092255.f -> xw1757092255
	if strings.HasSuffix(relPath, ".f") && strings.HasPrefix(filepath.Base(relPath), "xw") {
		return strings.TrimSuffix(filepath.Base(relPath), ".f"), nil
	}
	
	// Standard blob pattern: {prefix}/{3chars}/{rest}.f -> {prefix}{3chars}{rest}
	parts := strings.Split(relPath, "/")
	if len(parts) == 3 && strings.HasSuffix(parts[2], ".f") {
		prefix := parts[0]                                    // "p", "q", "s", "x", etc.
		subdir := parts[1]                                   // "010", "n0_", etc.
		filename := strings.TrimSuffix(parts[2], ".f")       // rest without .f
		return prefix + subdir + filename, nil
	}
	
	return "", fmt.Errorf("unknown file pattern: %s", relPath)
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
		fmt.Printf("✓ GCS→Local verification: All GCS blobs found locally!\n")
	} else {
		fmt.Printf("✗ GCS→Local verification failed: %d mismatches/errors\n", errors)
		return
	}

	// Reverse verification: Local → GCS
	fmt.Printf("\nStarting Local→GCS verification...\n")
	
	// Create a map of GCS blobs for fast lookup
	gcsMap := make(map[string]bool)
	for _, blob := range gcsBlobs {
		gcsMap[blob.Name] = true
	}
	
	var localFiles []string
	var localErrors int
	
	// Walk the repository directory to find all local files
	err = filepath.Walk("/var/kopia/repository", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if info.IsDir() {
			return nil
		}
		
		// Skip cache files, temporary files, and internal Kopia files
		if strings.Contains(path, "/.cache/") || 
		   strings.HasSuffix(path, ".tmp") ||
		   strings.HasSuffix(path, ".shards") ||
		   strings.Contains(path, "/.") {
			return nil
		}
		
		localFiles = append(localFiles, path)
		return nil
	})
	
	if err != nil {
		fmt.Printf("Error walking repository: %v\n", err)
		return
	}
	
	fmt.Printf("Found %d local files\n", len(localFiles))
	
	var localMatched, localMissing int
	
	for i, localPath := range localFiles {
		if i > 0 && i%100 == 0 {
			fmt.Printf("Local progress: %d/%d files processed\n", i, len(localFiles))
		}
		
		blobName, err := convertLocalPathToBlobName(localPath)
		if err != nil {
			fmt.Printf("Error converting path %s: %v\n", localPath, err)
			localErrors++
			continue
		}
		
		if gcsMap[blobName] {
			localMatched++
		} else {
			fmt.Printf("LOCAL FILE MISSING FROM GCS: %s → %s\n", localPath, blobName)
			localMissing++
		}
	}
	
	fmt.Printf("\nLocal→GCS Verification Results:\n")
	fmt.Printf("  Found in GCS: %d/%d files\n", localMatched, len(localFiles))
	if localMissing > 0 {
		fmt.Printf("  Missing from GCS: %d\n", localMissing)
	}
	if localErrors > 0 {
		fmt.Printf("  Conversion errors: %d\n", localErrors)
	}
	
	if localMatched == len(localFiles) && localMissing == 0 && localErrors == 0 {
		fmt.Printf("✓ Local→GCS verification: All local files found in GCS!\n")
		fmt.Printf("🎉 PERFECT BIDIRECTIONAL VERIFICATION: %d files match in both directions!\n", localMatched)
	} else {
		fmt.Printf("✗ Local→GCS verification failed: %d missing + %d errors\n", localMissing, localErrors)
	}
}
