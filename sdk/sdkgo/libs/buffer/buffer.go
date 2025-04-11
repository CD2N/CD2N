package buffer

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/CD2N/CD2N/sdk/sdkgo/libs/cache"
	"github.com/pkg/errors"
)

const (
	UNNAMED_FILENAME = "Unnamed"
)

type FileBuffer struct {
	cacher *cache.Cache
	bufDir string
}

func NewFileBuffer(limitSize uint64, dir string) (*FileBuffer, error) {
	c := cache.NewCache(limitSize)
	c.RegisterSwapoutCallbacksCallbacks(func(i cache.Item) {
		if i.Value != "" {
			os.Remove(i.Value)
		}
	})
	go func() {
		defer func() {
			err := recover()
			if err != nil {
				log.Println(err)
			}
		}()
		err := c.LoadCacheRecordsWithFiles(dir)
		if err != nil {
			log.Println(errors.Wrap(err, "new file buffer error"))
		}
	}()
	return &FileBuffer{
		cacher: c,
		bufDir: dir,
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
}

func (b *FileBuffer) GetData(key string) cache.Item {
	return b.cacher.Get(key)
}

func (b *FileBuffer) RemoveData(fpath string) error {
	if err := os.Remove(fpath); err != nil {
		return errors.Wrap(err, "remove file buffer error")
	}
	b.cacher.RemoveItem(filepath.Base(fpath))
	return nil
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
