package lru

import (
	"container/list"
	"fmt"
)

type EvictCallback func(key interface{}, value interface{})

type LRU struct {
	maxSize   int
	evictList *list.List
	items     map[interface{}]*list.Element
	onEvict   EvictCallback
}

type entry struct {
	key   interface{}
	value interface{}
}

// CreateLRU creates an LRU of the maximum size
func CreateLRU(size int, onEvict EvictCallback) (*LRU, error) {
	if size <= 0 {
		return nil, fmt.Errorf("CreateLRU must take a positive maximum size.")
	}

	return &LRU{
		maxSize:   size,
		evictList: list.New(),
		items:     make(map[interface{}]*list.Element),
		onEvict:   onEvict,
	}, nil
}

// Add adds an item to cache.
func (c *LRU) Add(key, value interface{}) error {
	// Check for existing item
	if ent, ok := c.items[key]; ok {
		c.evictList.MoveToFront(ent)
		ent.Value.(*entry).value = value
		return nil
	}

	// Add a new item
	ent := &entry{key, value}
	entry := c.evictList.PushFront(ent)
	c.items[key] = entry

	// Evict the oldest element
	if c.evictList.Len() > c.maxSize {
		c.removeOldest()
	}
	return nil
}

// Get looks up a key's value from the cache and updates its recent-ness
func (c *LRU) Get(key interface{}) (interface{}, bool) {
	if ent, ok := c.items[key]; ok {
		c.evictList.MoveToFront(ent)
		return ent.Value.(*entry).value, true
	}
	return nil, false
}

// Len returns the number of items in the cache.
func (c *LRU) Len() int {
	return c.evictList.Len()
}

func (c *LRU) removeOldest() {
	ent := c.evictList.Back()
	if ent != nil {
		c.removeElement(ent)
	}
}

func (c *LRU) removeElement(e *list.Element) {
	c.evictList.Remove(e)
	kv := e.Value.(*entry)
	delete(c.items, kv.key)
	if c.onEvict != nil {
		c.onEvict(kv.key, kv.value)
	}
}

// Keys returns a slice of the keys in the cache, from oldest to newest.
func (c *LRU) Keys() []interface{} {
	keys := make([]interface{}, len(c.items))
	i := 0
	for ent := c.evictList.Back(); ent != nil; ent = ent.Prev() {
		keys[i] = ent.Value.(*entry).key
		i++
	}
	return keys
}
