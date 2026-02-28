/**
 * Session Manager
 * Manages chat sessions - ensures only 2 users per session
 * Tracks active connections and handles session lifecycle
 */

class SessionManager {
  constructor() {
    // Map of sessionId -> { users: [ws1, ws2], salt: string, createdAt: number }
    this.sessions = new Map();
  }

  /**
   * Create a new session with the provided salt
   * @param {string} sessionId - Hashed session code
   * @param {string} salt - Random salt for key derivation (hex string)
   * @returns {boolean} - Success status
   */
  createSession(sessionId, salt) {
    if (this.sessions.has(sessionId)) {
      return false;
    }

    this.sessions.set(sessionId, {
      users: [],
      salt: salt,
      createdAt: Date.now()
    });

    return true;
  }

  /**
   * Add user to session
   * @param {string} sessionId - Hashed session code
   * @param {WebSocket} ws - User's WebSocket connection
   * @returns {Object} - { success: boolean, userCount: number, salt: string, error: string }
   */
  joinSession(sessionId, salt, ws) {
    let session = this.sessions.get(sessionId);

    // If session doesn't exist, create it
    if (!session) {
      this.createSession(sessionId, salt);
      session = this.sessions.get(sessionId);
    }

    // Check if session is full (max 2 users)
    if (session.users.length >= 2) {
      return {
        success: false,
        error: 'Session is full (maximum 2 users)',
        userCount: session.users.length
      };
    }

    // Add user to session
    session.users.push(ws);

    return {
      success: true,
      userCount: session.users.length,
      salt: session.salt,
      error: null
    };
  }

  /**
   * Remove user from session and cleanup if empty
   * @param {string} sessionId - Hashed session code
   * @param {WebSocket} ws - User's WebSocket connection
   */
  leaveSession(sessionId, ws) {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    // Remove user from session
    session.users = session.users.filter(user => user !== ws);

    // Auto-destroy session when both users disconnect
    if (session.users.length === 0) {
      this.sessions.delete(sessionId);
      console.log(`[Session] Session ${sessionId.substring(0, 8)}... destroyed (empty)`);
    }
  }

  /**
   * Broadcast encrypted message to other user in session
   * @param {string} sessionId - Hashed session code
   * @param {WebSocket} senderWs - Sender's WebSocket
   * @param {Object} encryptedData - Encrypted message data
   */
  broadcastToSession(sessionId, senderWs, encryptedData) {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    // Send to all users in session except sender
    session.users.forEach(ws => {
      if (ws !== senderWs && ws.readyState === 1) { // WebSocket.OPEN
        try {
          ws.send(JSON.stringify(encryptedData));
        } catch (error) {
          console.error('[Session] Error broadcasting message:', error.message);
        }
      }
    });
  }

  /**
   * Get session info
   * @param {string} sessionId - Hashed session code
   * @returns {Object|null} - Session info or null
   */
  getSession(sessionId) {
    return this.sessions.get(sessionId) || null;
  }

  /**
   * Get total active sessions count
   * @returns {number}
   */
  getActiveSessionsCount() {
    return this.sessions.size;
  }

  /**
   * Clean up stale sessions (older than 24 hours)
   */
  cleanupStaleSessions() {
    const MAX_AGE = 24 * 60 * 60 * 1000; // 24 hours
    const now = Date.now();

    for (const [sessionId, session] of this.sessions.entries()) {
      if (now - session.createdAt > MAX_AGE) {
        // Close all connections
        session.users.forEach(ws => {
          if (ws.readyState === 1) {
            ws.close(1000, 'Session expired');
          }
        });
        this.sessions.delete(sessionId);
        console.log(`[Session] Cleaned up stale session ${sessionId.substring(0, 8)}...`);
      }
    }
  }
}

export default SessionManager;
