package buffer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/CD2N/CD2N/sdk/sdkgo/libs/cache"
	"github.com/pkg/errors"
)

const (
	UNNAMED_FILENAME = "Unnamed"
	SERIALIZED_LIMIT = 5
	UPDATE_TIME      = 5 * time.Minute
	METADATA         = "buffer_metadata.json"
)

type FileBuffer struct {
	cacher       *cache.Cache
	bufDir       string
	updateAt     *atomic.Value
	unserialized *atomic.Uint64
}

func NewFileBuffer(limitSize uint64, dir string) (*FileBuffer, error) {
	c := cache.NewCache(limitSize)
	c.RegisterSwapoutCallbacksCallbacks(func(i cache.Item) {
		if i.Value != "" {
			os.Remove(i.Value)
		}
	})
	c.LoadCacheRecords(filepath.Join(dir, METADATA))
	//go c.LoadCacheRecordsWithFiles(dir)

	update := &atomic.Value{}
	update.Store(time.Now())

	return &FileBuffer{
		cacher:       c,
		bufDir:       dir,
		updateAt:     update,
		unserialized: &atomic.Uint64{},
	}, nil
}

func (b *FileBuffer) NewBufPath(paths ...string) (string, error) {
	fpath := filepath.Join(append([]string{b.bufDir}, paths...)...)
	if len(paths) < 2 {
		return fpath, nil
	}
	dir := filepath.Dir(fpath)
	if _, err := os.Stat(dir); err == nil {
		return fpath, nil
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", errors.Wrap(err, "new buffer path error")
	}
	return fpath, nil
}

func (b *FileBuffer) NewBufDir(subdirs ...string) (string, error) {
	dir := filepath.Join(append([]string{b.bufDir}, subdirs...)...)
	if _, err := os.Stat(dir); err == nil {
		return dir, nil
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", errors.Wrap(err, "new buffer dir error")
	}
	return dir, nil
}

func (b *FileBuffer) JoinPath(baseDir string, subpath ...string) (string, error) {
	fpath := filepath.Join(append([]string{baseDir}, subpath...)...)
	if _, err := os.Stat(baseDir); err == nil {
		return fpath, nil
	}
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return "", errors.Wrap(err, "new buffer dir error")
	}
	return fpath, nil
}

func (b *FileBuffer) AddData(key, fpath string) {

	f, err := os.Stat(ExtraPath(fpath))
	if err != nil {
		return
	}
	b.cacher.AddWithData(key, fpath, f.Size())
	b.unserialized.Add(1)
	if b.unserialized.Load() >= SERIALIZED_LIMIT || time.Since(b.updateAt.Load().(time.Time)) >= UPDATE_TIME {
		b.updateAt.Store(time.Now())
		b.cacher.SaveCacheRecords(filepath.Join(b.bufDir, METADATA))
		b.unserialized.Store(0)
	}
}

func (b *FileBuffer) GetData(key string) cache.Item {
	return b.cacher.Get(key)
}

func (b *FileBuffer) RemoveData(fpath string) error {
	b.cacher.RemoveItem(filepath.Base(fpath))
	b.unserialized.Add(1)
	if b.unserialized.Load() >= SERIALIZED_LIMIT || time.Since(b.updateAt.Load().(time.Time)) >= UPDATE_TIME {
		b.updateAt.Store(time.Now())
		b.cacher.SaveCacheRecords(filepath.Join(b.bufDir, METADATA))
		b.unserialized.Store(0)
	}
	if err := os.Remove(fpath); err != nil {
		return errors.Wrap(err, "remove file buffer error")
	}
	return nil
}

func (b *FileBuffer) BufferStatus() cache.Info {
	return b.cacher.Status()
}

func CatNamePath(name, path string) string {
	return fmt.Sprintf("%s-=+>%s", name, path)
}

func SplitNamePath(namepath string) (string, string) {
	strs := strings.Split(namepath, "-=+>")
	if len(strs) != 2 {
		return UNNAMED_FILENAME, strs[len(strs)-1]
	}
	return strs[0], strs[1]
}

func ExtraPath(fpath string) string {
	n, p := SplitNamePath(fpath)
	if strings.Contains(n, UNNAMED_FILENAME) {
		p = fpath
	}
	return p
}
