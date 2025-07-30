package cache

import (
	"sync"
	"time"
)

// Cache 缓存接口
type Cache interface {
	Get(key string) interface{}
	Set(key string, value interface{})
	Delete(key string)
	Clear()
	Close() error
}

// MemoryCache 内存缓存实现
type MemoryCache struct {
	mu    sync.RWMutex
	items map[string]*cacheItem
	ttl   time.Duration
}

type cacheItem struct {
	value     interface{}
	expiresAt time.Time
}

// NewMemoryCache 创建内存缓存
func NewMemoryCache(ttl time.Duration) *MemoryCache {
	cache := &MemoryCache{
		items: make(map[string]*cacheItem),
		ttl:   ttl,
	}

	// 启动清理协程
	go cache.cleanup()

	return cache
}

// Get 获取缓存值
func (c *MemoryCache) Get(key string) interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, exists := c.items[key]
	if !exists {
		return nil
	}

	if time.Now().After(item.expiresAt) {
		delete(c.items, key)
		return nil
	}

	return item.value
}

// Set 设置缓存值
func (c *MemoryCache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = &cacheItem{
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// Delete 删除缓存值
func (c *MemoryCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.items, key)
}

// Clear 清空缓存
func (c *MemoryCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[string]*cacheItem)
}

// Close 关闭缓存
func (c *MemoryCache) Close() error {
	c.Clear()
	return nil
}

// cleanup 清理过期项
func (c *MemoryCache) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, item := range c.items {
			if now.After(item.expiresAt) {
				delete(c.items, key)
			}
		}
		c.mu.Unlock()
	}
}

// NoOpCache 空操作缓存实现
type NoOpCache struct{}

// NewNoOpCache 创建空操作缓存
func NewNoOpCache() *NoOpCache {
	return &NoOpCache{}
}

// Get 获取缓存值（总是返回nil）
func (c *NoOpCache) Get(key string) interface{} {
	return nil
}

// Set 设置缓存值（不执行任何操作）
func (c *NoOpCache) Set(key string, value interface{}) {
	// 不执行任何操作
}

// Delete 删除缓存值（不执行任何操作）
func (c *NoOpCache) Delete(key string) {
	// 不执行任何操作
}

// Clear 清空缓存（不执行任何操作）
func (c *NoOpCache) Clear() {
	// 不执行任何操作
}

// Close 关闭缓存
func (c *NoOpCache) Close() error {
	return nil
}
