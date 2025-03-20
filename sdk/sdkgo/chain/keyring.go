package chain

import (
	"math/rand"
	"sync"

	"slices"

	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
)

type KeyLocker struct {
	shards []*shard
}

type shard struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func NewKeyLocker(shardCount int) *KeyLocker {
	shards := make([]*shard, shardCount)
	for i := range shards {
		shards[i] = &shard{
			locks: make(map[string]*sync.Mutex),
		}
	}
	return &KeyLocker{
		shards: shards,
	}
}

func (kl *KeyLocker) getShard(key string) *shard {
	hash := fnv32(key)
	return kl.shards[hash%uint32(len(kl.shards))]
}

func fnv32(key string) uint32 {
	hash := uint32(2166136261)
	for i := range len(key) {
		hash *= 16777619
		hash ^= uint32(key[i])
	}
	return hash
}

func (kl *KeyLocker) Lock(key string) {
	shard := kl.getShard(key)
	shard.mu.Lock()
	if _, ok := shard.locks[key]; !ok {
		shard.locks[key] = &sync.Mutex{}
	}
	lock := shard.locks[key]
	shard.mu.Unlock()
	lock.Lock()
}

func (kl *KeyLocker) Unlock(key string) {
	shard := kl.getShard(key)
	shard.mu.Lock()
	lock, ok := shard.locks[key]
	shard.mu.Unlock()

	if ok {
		lock.Unlock()
	}
}

func (kl *KeyLocker) Cleanup() {
	for _, shard := range kl.shards {
		shard.mu.Lock()
		for key, lock := range shard.locks {
			if lock.TryLock() {
				lock.Unlock()
				delete(shard.locks, key)
			}
		}
		shard.mu.Unlock()
	}
}

type KeyringManager interface {
	AddKey(key signature.KeyringPair)
	RemoveKey(address string)
	GetKey(address string) signature.KeyringPair
	GetKeyRandomly() signature.KeyringPair
	GetKeyInOrder() signature.KeyringPair
	PutKey(address string)
}

type Keyrings struct {
	lock     *KeyLocker
	keyMap   *sync.Map
	mu       *sync.Mutex
	index    int
	keyrings []signature.KeyringPair
}

func NewKeyrings(keyrings ...signature.KeyringPair) *Keyrings {
	keyMap := &sync.Map{}
	for i, key := range keyrings {
		keyMap.Store(key.Address, i)
	}
	return &Keyrings{
		lock:     NewKeyLocker(len(keyrings)/1024 + 1),
		keyMap:   keyMap,
		mu:       &sync.Mutex{},
		keyrings: keyrings,
	}
}

func (k *Keyrings) AddKey(key signature.KeyringPair) {
	if key.URI == "" {
		return
	}
	if _, ok := k.keyMap.LoadOrStore(key.Address, len(k.keyrings)); ok {
		return
	}
	k.keyrings = append(k.keyrings, key)
}

func (k *Keyrings) RemoveKey(address string) {
	if address == "" {
		return
	}
	if _, ok := k.keyMap.Load(address); !ok {
		return
	}
	for i, key := range k.keyrings {
		if key.Address != address {
			continue
		}
		if i == 0 {
			k.keyrings = k.keyrings[1:]
		} else if i == len(k.keyrings)-1 {
			k.keyrings = k.keyrings[:i]
		} else {
			k.keyrings = slices.Delete(k.keyrings, i, i+1)
		}
		k.keyMap.Delete(address)
		k.lock.Cleanup()
		return
	}
}

func (k *Keyrings) GetKey(address string) signature.KeyringPair {
	if address == "" {
		return signature.KeyringPair{}
	}
	v, ok := k.keyMap.Load(address)
	if !ok {
		return signature.KeyringPair{}
	}
	k.lock.Lock(address)
	return k.keyrings[v.(int)]
}

func (k *Keyrings) GetKeyInOrder() signature.KeyringPair {
	if len(k.keyrings) <= 0 {
		return signature.KeyringPair{}
	}
	var idx int
	k.mu.Lock()
	idx = k.index
	k.index = (k.index + 1) % len(k.keyrings)
	k.mu.Unlock()
	return k.keyrings[idx]
}

func (k *Keyrings) GetKeyRandomly() signature.KeyringPair {
	if len(k.keyrings) <= 0 {
		return signature.KeyringPair{}
	}
	i := rand.Intn(len(k.keyrings))
	key := k.keyrings[i]
	k.lock.Lock(key.Address)
	return key
}

func (k *Keyrings) PutKey(address string) {
	k.lock.Unlock(address)
}
