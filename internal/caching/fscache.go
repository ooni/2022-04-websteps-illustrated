// Package caching implements an on-disk cache.
package caching

//
// FSCache
//
// Contains a file system cache derived from golang build cache.
//

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ooni/2022-04-websteps-illustrated/internal/model"
	"github.com/rogpeppe/go-internal/lockedfile"
)

// FSCache provides a simple cache-on-filesystem functionality.
type FSCache struct {
	dirpath string
	now     func() time.Time
}

// NewFSCache creates a new simpleCache instance.
func NewFSCache(dirpath string) *FSCache {
	return &FSCache{
		dirpath: dirpath,
		now:     time.Now,
	}
}

var _ model.KeyValueStore = &FSCache{}

// Get implements KeyValueStore.Get.
func (sc *FSCache) Get(key string) ([]byte, error) {
	_, fpath := sc.fsmap(key)
	return lockedfile.Read(fpath)
}

// Set implements KeyValueStore.Set.
func (sc *FSCache) Set(key string, value []byte) error {
	dpath, fpath := sc.fsmap(key)
	const dperms = 0700
	if err := os.MkdirAll(dpath, dperms); err != nil {
		return err
	}
	const fperms = 0600
	if err := lockedfile.Write(fpath, bytes.NewReader(value), fperms); err != nil {
		return err
	}
	sc.maybeMarkAsUsed(fpath)
	return nil
}

// fsmap maps a given key to a directory and a file paths.
func (sc *FSCache) fsmap(key string) (dpath, fpath string) {
	hs := sha256.Sum256([]byte(key))
	dpath = filepath.Join(sc.dirpath, fmt.Sprintf("%02x", hs[0]))
	fpath = filepath.Join(dpath, fmt.Sprintf("%02x-d", hs))
	return
}

// Time constants for cache expiration.
//
// We set the mtime on a cache file on each use, but at most one per cacheMtimeInterval,
// to avoid causing many unnecessary inode updates. The mtimes therefore
// roughly reflect "time of last use" but may in fact be older.
//
// We scan the cache for entries to delete at most once per cacheTrimInterval.
//
// When we do scan the cache, we delete entries that have not been used for
// at least cacheTrimLimit. This code was adapted from Go internals and the original
// code has numbers based on statistics. We should do the same for OONI.
//
// SPDX-License-Identifier: BSD-3-Clause
//
// Source: https://github.com/rogpeppe/go-internal/commit/797a764460877f0a4bd570a61d60d10815e728e6
const (
	cacheMtimeInterval = 15 * time.Minute
	cacheTrimInterval  = 45 * time.Minute
	cacheTrimLimit     = 2 * time.Hour
)

// maybeMarkAsUsed makes a best-effort attempt to update mtime on file,
// so that mtime reflects cache access time.
//
// Because the reflection only needs to be approximate,
// and to reduce the amount of disk activity caused by using
// cache entries, maybeMarkAsUsed only updates the mtime if the current
// mtime is more than an mtimeInterval old. This heuristic eliminates
// nearly all of the mtime updates that would otherwise happen,
// while still keeping the mtimes useful for cache trimming.
//
// SPDX-License-Identifier: BSD-3-Clause
//
// Source: https://github.com/rogpeppe/go-internal/commit/797a764460877f0a4bd570a61d60d10815e728e6
func (sc *FSCache) maybeMarkAsUsed(file string) {
	info, err := os.Stat(file)
	now := sc.now()
	if err == nil && now.Sub(info.ModTime()) < cacheMtimeInterval {
		return
	}
	os.Chtimes(file, now, now)
}

// Trim removes old cache entries that are likely not to be reused.
//
// SPDX-License-Identifier: BSD-3-Clause
//
// Source: https://github.com/rogpeppe/go-internal/commit/797a764460877f0a4bd570a61d60d10815e728e6
func (sc *FSCache) Trim() {
	now := sc.now()

	trimfilepath := filepath.Join(sc.dirpath, "trim.txt")

	// We maintain in dir/trim.txt the time of the last completed cache trim.
	// If the cache has been trimmed recently enough, do nothing.
	// This is the common case.
	data, _ := os.ReadFile(trimfilepath)
	lt, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err == nil && now.Sub(time.Unix(lt, 0)) < cacheTrimInterval {
		return
	}

	// Trim each of the 256 subdirectories.
	// We subtract an additional mtimeInterval
	// to account for the imprecision of our "last used" mtimes.
	cutoff := now.Add(-cacheTrimLimit - cacheMtimeInterval)
	for i := 0; i < 256; i++ {
		subdir := filepath.Join(sc.dirpath, fmt.Sprintf("%02x", i))
		sc.trimSubdir(subdir, cutoff)
	}

	os.WriteFile(trimfilepath, []byte(fmt.Sprintf("%d", now.Unix())), 0666)
}

// trimSubdir trims a single cache subdirectory.
//
// SPDX-License-Identifier: BSD-3-Clause
//
// Source: https://github.com/rogpeppe/go-internal/commit/797a764460877f0a4bd570a61d60d10815e728e6
func (sc *FSCache) trimSubdir(subdir string, cutoff time.Time) {
	// Read all directory entries from subdir before removing
	// any files, in case removing files invalidates the file offset
	// in the directory scan. Also, ignore error from df.Readdirnames,
	// because we don't care about reporting the error and we still
	// want to process any entries found before the error.
	df, err := os.Open(subdir)
	if err != nil {
		return
	}
	names, _ := df.Readdirnames(-1)
	df.Close()

	for _, name := range names {
		// Remove only cache entries (xxxx-a and xxxx-d).
		if !strings.HasSuffix(name, "-a") && !strings.HasSuffix(name, "-d") {
			continue
		}
		entry := filepath.Join(subdir, name)
		info, err := os.Stat(entry)
		if err == nil && info.ModTime().Before(cutoff) {
			os.Remove(entry)
		}
	}
}
