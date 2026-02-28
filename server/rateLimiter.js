/**
 * Rate Limiter
 * Implements basic rate limiting to prevent abuse
 * Tracks requests per IP/connection
 */

class RateLimiter {
  constructor() {
    // Map of identifier -> { count: number, resetTime: number }
    this.requests = new Map();
    
    // Configuration
    this.config = {
      maxRequestsPerMinute: 60,
      maxMessagesPerMinute: 30,
      windowMs: 60 * 1000 // 1 minute
    };
  }

  /**
   * Check if request should be rate limited
   * @param {string} identifier - IP address or connection ID
   * @param {string} type - 'request' or 'message'
   * @returns {boolean} - true if allowed, false if rate limited
   */
  checkLimit(identifier, type = 'request') {
    const now = Date.now();
    const limit = type === 'message' 
      ? this.config.maxMessagesPerMinute 
      : this.config.maxRequestsPerMinute;

    let record = this.requests.get(identifier);

    // Create new record if doesn't exist or window expired
    if (!record || now > record.resetTime) {
      record = {
        count: 0,
        resetTime: now + this.config.windowMs
      };
      this.requests.set(identifier, record);
    }

    // Increment count
    record.count++;

    // Check if over limit
    if (record.count > limit) {
      return false;
    }

    return true;
  }

  /**
   * Clean up expired records
   */
  cleanup() {
    const now = Date.now();
    for (const [identifier, record] of this.requests.entries()) {
      if (now > record.resetTime) {
        this.requests.delete(identifier);
      }
    }
  }

  /**
   * Reset limit for specific identifier
   * @param {string} identifier - IP address or connection ID
   */
  reset(identifier) {
    this.requests.delete(identifier);
  }
}

export default RateLimiter;
