package cache

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pkg/errors"
)

const (
	DEFAULT_LIMIT_SIZE = 2 * 1014 * 1024 * 1024 * 1024
)

type Item struct {
	Key       string
	Value     string
	Size      int64
	Freq      int
	AccessOn  time.Time
	Next, Pre *Item
}

type Cache struct {
	cacheSize        uint64
	cacheLimit       uint64
	itemNum          uint64
	cache            map[string]*Item
	head, tail       *Item
	addCallbacks     []func(Item)
	swapoutCallbacks []func(Item)
	lock             *sync.Mutex
}

func NewCache(limitSize uint64) *Cache {
	if limitSize == 0 {
		limitSize = DEFAULT_LIMIT_SIZE
	}
	head, tail := &Item{}, &Item{}
	head.Next = tail
	tail.Pre = head
	return &Cache{
		cacheLimit: limitSize,
		cache:      map[string]*Item{},
		lock:       &sync.Mutex{},
		head:       head,
		tail:       tail,
	}
}

func (c *Cache) Get(key string) Item {
	var item Item
	c.lock.Lock()
	defer c.lock.Unlock()
	if v, ok := c.cache[key]; ok {
		item.Value = v.Value
		item.AccessOn = v.AccessOn
		item.Freq = v.Freq
		item.Size = v.Size
		item.Key = key
		v.AccessOn = time.Now()
		v.Freq++
		c.removeItem(v)
		c.moveToHead(v)
	}
	return item
}

func (c *Cache) Add(key string, size int64) {
	c.AddWithData(key, "", size)
}

func (c *Cache) AddWithData(key, data string, size int64) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if v, ok := c.cache[key]; ok {
		v.AccessOn = time.Now()
		v.Freq += 1
		v.Value = data
		v.Size = size
		c.removeItem(v)
		c.moveToHead(v)
		return
	}
	item := &Item{
		Key:      key,
		Value:    data,
		Size:     size,
		Freq:     1,
		AccessOn: time.Now(),
	}
	c.cache[key] = item
	c.moveToHead(item)
	c.itemNum++
	c.cacheSize += uint64(size)
	for c.cacheSize >= c.cacheLimit*9/10 && c.itemNum > 0 {
		item = c.tail.Pre
		c.removeItem(item)
		delete(c.cache, item.Key)
		c.cacheSize -= uint64(item.Size)
		c.itemNum--
		for _, call := range c.swapoutCallbacks {
			call(*item)
		}
	}
}

func (c *Cache) removeItem(item *Item) {
	item.Pre.Next = item.Next
	item.Next.Pre = item.Pre
}

func (c *Cache) moveToHead(item *Item) {
	item.Next = c.head.Next
	item.Pre = c.head
	c.head.Next.Pre = item
	c.head.Next = item

	for _, call := range c.addCallbacks {
		call(*item)
	}
}

func (c Cache) RemoveItem(key string) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if v, ok := c.cache[key]; ok {
		c.removeItem(v)
		delete(c.cache, v.Key)
		c.cacheSize -= uint64(v.Size)
		c.itemNum--
	}
}

func (c *Cache) RegisterAddCallbacks(handles ...func(Item)) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.addCallbacks = append(c.addCallbacks, handles...)
}

func (c *Cache) RegisterSwapoutCallbacksCallbacks(handles ...func(Item)) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.swapoutCallbacks = append(c.swapoutCallbacks, handles...)
}

func (c *Cache) SaveCacheRecords(fpath string) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	items := make([]Item, 0, c.itemNum)
	for p := c.head.Next; p != c.tail; p = p.Next {
		items = append(items, Item{
			Key:      p.Key,
			Size:     p.Size,
			Freq:     p.Freq,
			AccessOn: p.AccessOn,
		})
	}
	jbytes, err := json.Marshal(items)
	if err != nil {
		return errors.Wrap(err, "save cache records")
	}
	f, err := os.Create(fpath)
	if err != nil {
		return errors.Wrap(err, "save cache records")
	}
	defer f.Close()
	_, err = f.Write(jbytes)
	return errors.Wrap(err, "save cache records")
}

func (c *Cache) LoadCacheRecords(fpath string) error {
	var items []Item
	jbytes, err := os.ReadFile(fpath)
	if err != nil {
		return errors.Wrap(err, "load cache records")
	}
	err = json.Unmarshal(jbytes, &items)
	if err != nil {
		return errors.Wrap(err, "load cache records")
	}
	for i := len(items) - 1; i > 0; i-- {
		c.Add(items[i].Key, items[i].Size)
	}
	return nil
}

func (c *Cache) LoadCacheRecordsWithFiles(dir string) error {
	err := filepath.Walk(dir, func(path string, info fs.FileInfo, err error) (rerr error) {
		defer func() {
			if e := recover(); e != nil {
				rerr = fmt.Errorf("%v", e)
			}

		}()
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		c.AddWithData(info.Name(), path, info.Size())
		return nil
	})
	return errors.Wrap(err, "load cache records error")
}
