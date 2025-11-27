/**
 * Storage abstraction layer for serverless-compatible secret storage
 * Supports multiple backends: Redis (Vercel KV), Vercel Runtime, Memory
 */

const crypto = require('crypto');

class StorageManager {
  constructor() {
    this.backend = this.detectBackend();
    this.initialized = false;
  }

  detectBackend() {
    // Check for REDIS_URL first (your current setup - highest priority)
    if (process.env.REDIS_URL) {
      console.log('🔗 Using Redis storage via REDIS_URL');
      return 'redis-url';
    }

    // Check for Upstash Redis REST API
    if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
      console.log('🔗 Using Upstash Redis storage');
      return 'upstash-redis';
    }

    // Check if we're in Vercel environment with KV available
    if (process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN) {
      console.log('🔗 Using Vercel KV (Redis) storage');
      return 'vercel-kv';
    }

    // Also check for direct KV_URL as fallback
    if (process.env.KV_URL) {
      console.log('🔗 Using Vercel KV (Redis) storage via KV_URL');
      return 'vercel-kv';
    }

    // Check if we're in Vercel production environment
    if (process.env.VERCEL && process.env.NODE_ENV === 'production') {
      console.log('☁️ Using Vercel runtime storage');
      return 'vercel-runtime';
    }

    // Fallback to memory storage for development
    console.log('💾 Using in-memory storage (development)');
    return 'memory';
  }

  async initialize() {
    if (this.initialized) return;

    switch (this.backend) {
      case 'upstash-redis':
        await this.initUpstashRedis();
        break;
      case 'redis-url':
        await this.initRedisUrl();
        break;
      case 'vercel-kv':
        await this.initVercelKV();
        break;
      case 'vercel-runtime':
        await this.initVercelRuntime();
        break;
      case 'memory':
        await this.initMemory();
        break;
    }

    this.initialized = true;
  }

  async initUpstashRedis() {
    try {
      // Import Upstash Redis client dynamically for serverless compatibility
      const { Redis } = await import('@upstash/redis');

      this.redis = new Redis({
        url: process.env.UPSTASH_REDIS_REST_URL,
        token: process.env.UPSTASH_REDIS_REST_TOKEN,
      });

      // Test connection
      await this.redis.ping();
      console.log('✅ Upstash Redis connected successfully');
    } catch (error) {
      console.error('❌ Failed to connect to Upstash Redis:', error);
      throw new Error('Upstash Redis initialization failed');
    }
  }

  async initRedisUrl() {
    try {
      // Check if this is Upstash Redis or regular Redis
      const redisUrl = process.env.REDIS_URL;

      if (!redisUrl) {
        throw new Error('REDIS_URL environment variable is not set');
      }

      console.log(`🔗 Attempting to connect to Redis with URL: ${redisUrl.replace(/:.*@/, ':***@')}`);

      // Check for Upstash-specific patterns in URL
      const isUpstash = redisUrl && (
        redisUrl.includes('upstash.io') ||
        redisUrl.includes('upstash') ||
        process.env.UPSTASH_REDIS_REST_TOKEN
      );

      if (isUpstash) {
        // For Upstash, use REST API client
        const { Redis } = await import('@upstash/redis');

        let clientConfig;
        if (redisUrl.startsWith('rediss://') || redisUrl.startsWith('redis://')) {
          // Parse redis:// URL to extract host and credentials for REST API
          const url = new URL(redisUrl);
          const restUrl = `https://${url.hostname}`;
          clientConfig = {
            url: restUrl,
            token: url.password
          };
          console.log(`🔗 Converting Upstash Redis URL to REST API: ${restUrl}`);
        } else {
          clientConfig = { url: redisUrl };
        }

        this.redis = new Redis(clientConfig);
      } else {
        // For Redis.com and other standard Redis, use node-redis client
        const redis = await import('redis');
        console.log('🔗 Detected standard Redis, using node-redis client');
        this.redis = redis.createClient({
          url: redisUrl,
          socket: {
            connectTimeout: 5000,
            lazyConnect: true
          }
        });

        this.redis.on('error', (err) => {
          console.error('Redis Client Error:', err.message);
        });

        this.redis.on('connect', () => {
          console.log('🔗 Redis client connecting...');
        });

        this.redis.on('ready', () => {
          console.log('✅ Redis client ready');
        });
      }

      // Test connection
      console.log('🔗 Testing Redis connection...');
      await this.redis.ping();
      console.log('✅ Redis connected successfully via REDIS_URL');
    } catch (error) {
      console.error('❌ Failed to connect to Redis via REDIS_URL:', {
        message: error.message,
        stack: error.stack,
        urlExists: !!process.env.REDIS_URL,
        urlFormat: process.env.REDIS_URL ? process.env.REDIS_URL.substring(0, 20) + '...' : 'none'
      });
      throw new Error(`Redis initialization failed: ${error.message}`);
    }
  }

  async initVercelKV() {
    try {
      // Import KV store dynamically for serverless compatibility
      const { createClient } = await import('@vercel/kv');

      // Use REST API variables first, fallback to direct KV_URL
      const kvUrl = process.env.KV_REST_API_URL || process.env.KV_URL;
      const kvToken = process.env.KV_REST_API_TOKEN;

      if (!kvUrl) {
        throw new Error('KV URL not found in environment variables');
      }

      const clientConfig = { url: kvUrl };
      if (kvToken) {
        clientConfig.token = kvToken;
      }

      this.kv = createClient(clientConfig);

      // Test connection
      await this.kv.ping();
      console.log('✅ Vercel KV connected successfully');
    } catch (error) {
      console.error('❌ Failed to connect to Vercel KV:', error);
      throw new Error('Vercel KV initialization failed');
    }
  }

  async initVercelRuntime() {
    // Vercel provides a simple key-value store in production
    // We'll use their KV-like storage if available, or fallback to memory
    try {
      // Check if we can access Vercel's KV through the runtime
      if (typeof globalThis.process?.env?.KV_URL !== 'undefined') {
        const { createClient } = await import('@vercel/kv');
        this.kv = createClient({
          url: globalThis.process.env.KV_URL,
        });
        console.log('✅ Vercel runtime KV connected');
      } else {
        console.log('⚠️ Vercel KV not available, using memory fallback');
        this.backend = 'memory';
        await this.initMemory();
      }
    } catch (error) {
      console.log('⚠️ Runtime storage failed, using memory fallback:', error.message);
      this.backend = 'memory';
      await this.initMemory();
    }
  }

  async initMemory() {
    this.memoryStore = new Map();
    console.log('✅ In-memory storage initialized');
  }

  /**
   * Store a secret with expiration
   */
  async setSecret(id, secretData, expirationMinutes) {
    await this.initialize();

    const expiresAt = Date.now() + (expirationMinutes * 60 * 1000);
    const data = {
      ...secretData,
      expiresAt,
      accessed: false
    };

    try {
      switch (this.backend) {
        case 'upstash-redis':
        case 'redis-url':
          // Store with TTL in seconds using Redis
          const redisTtlSeconds = expirationMinutes * 60;
          await this.redis.set(`secret:${id}`, JSON.stringify(data), { ex: redisTtlSeconds });
          break;

        case 'vercel-kv':
        case 'vercel-runtime':
          // Store with TTL in seconds
          const kvTtlSeconds = expirationMinutes * 60;
          await this.kv.set(`secret:${id}`, JSON.stringify(data), { ex: kvTtlSeconds });
          break;

        case 'memory':
          this.memoryStore.set(id, data);
          // Set up cleanup for memory storage
          this.scheduleCleanup(id, expirationMinutes * 60 * 1000);
          break;
      }

      return { success: true, expiresAt };
    } catch (error) {
      console.error('Failed to store secret:', error);
      throw new Error('Storage operation failed');
    }
  }

  /**
   * Retrieve and delete a secret (one-time access)
   */
  async getAndDeleteSecret(id) {
    await this.initialize();

    try {
      let secretData;

      switch (this.backend) {
        case 'upstash-redis':
        case 'redis-url':
          const redisRaw = await this.redis.get(`secret:${id}`);
          if (!redisRaw) return null;

          // Handle both string and object returns from Redis
          if (typeof redisRaw === 'string') {
            secretData = JSON.parse(redisRaw);
          } else if (typeof redisRaw === 'object') {
            secretData = redisRaw;
          } else {
            console.error('Unexpected Redis data type:', typeof redisRaw);
            return null;
          }

          // Delete immediately after retrieval
          await this.redis.del(`secret:${id}`);
          break;

        case 'vercel-kv':
        case 'vercel-runtime':
          const raw = await this.kv.get(`secret:${id}`);
          if (!raw) return null;

          secretData = JSON.parse(raw);
          // Delete immediately after retrieval
          await this.kv.del(`secret:${id}`);
          break;

        case 'memory':
          secretData = this.memoryStore.get(id);
          if (secretData) {
            this.memoryStore.delete(id);
          }
          break;
      }

      if (!secretData) {
        return null;
      }

      // Check if already accessed
      if (secretData.accessed) {
        return null;
      }

      // Check expiration
      if (Date.now() > secretData.expiresAt) {
        return null;
      }

      // Mark as accessed and return
      return {
        encryptedData: secretData.encryptedData,
        iv: secretData.iv
      };

    } catch (error) {
      console.error('Failed to retrieve secret:', error);
      throw new Error('Storage operation failed');
    }
  }

  /**
   * Schedule cleanup for memory storage
   */
  scheduleCleanup(id, delayMs) {
    setTimeout(() => {
      if (this.memoryStore.has(id)) {
        this.memoryStore.delete(id);
      }
    }, delayMs);
  }

  /**
   * Get storage statistics
   */
  async getStats() {
    await this.initialize();

    try {
      switch (this.backend) {
        case 'upstash-redis':
        case 'redis-url':
          // For Redis, we can get info about keys using SCAN
          try {
            const keys = await this.redis.keys('secret:*');
            return {
              backend: this.backend,
              activeSecrets: keys.length,
              uptime: process.uptime()
            };
          } catch (redisError) {
            // Fallback if keys command fails
            return {
              backend: this.backend,
              activeSecrets: -1, // Unknown count
              uptime: process.uptime(),
              error: 'Could not count keys'
            };
          }

        case 'vercel-kv':
        case 'vercel-runtime':
          // For Redis/KV, we can get info about keys
          const keys = await this.kv.keys('secret:*');
          return {
            backend: this.backend,
            activeSecrets: keys.length,
            uptime: process.uptime()
          };

        case 'memory':
          return {
            backend: this.backend,
            activeSecrets: this.memoryStore.size,
            uptime: process.uptime()
          };
      }
    } catch (error) {
      console.error('Failed to get stats:', error);
      return {
        backend: this.backend,
        activeSecrets: 0,
        uptime: process.uptime(),
        error: 'Stats unavailable'
      };
    }
  }

  /**
   * Health check for storage backend
   */
  async healthCheck() {
    try {
      await this.initialize();

      const testId = crypto.randomBytes(8).toString('hex');
      const testData = { test: true, timestamp: Date.now() };

      await this.setSecret(testId, testData, 1);
      const retrieved = await this.getAndDeleteSecret(testId);

      return retrieved && retrieved.test === testData.test;
    } catch (error) {
      console.error('Storage health check failed:', error);
      return false;
    }
  }
}

// Export singleton instance
const storage = new StorageManager();

module.exports = {
  storage,
  // Export class for testing
  StorageManager
};