/**
 * WebSocket Manager
 * 
 * Handles real-time communication with server
 * Manages connection lifecycle and message routing
 */

class SocketManager {
  constructor() {
    this.ws = null;
    this.isConnected = false;
    this.messageHandlers = new Map();
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.reconnectDelay = 2000;
    this.intentionalDisconnect = false; // Track intentional disconnects
  }

  /**
   * Connect to WebSocket server
   * @returns {Promise<void>}
   */
  connect() {
    return new Promise((resolve, reject) => {
      try {
        // Reset intentional disconnect flag when explicitly connecting
        this.intentionalDisconnect = false;
        
        // Determine WebSocket URL based on current location
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.host;
        const wsUrl = `${protocol}//${host}`;

        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
          console.log('[Socket] Connected to server');
          this.isConnected = true;
          this.reconnectAttempts = 0;
          this.emit('connected');
          resolve();
        };

        this.ws.onmessage = (event) => {
          try {
            const message = JSON.parse(event.data);
            this.handleMessage(message);
          } catch (error) {
            console.error('[Socket] Error parsing message:', error);
          }
        };

        this.ws.onerror = (error) => {
          console.error('[Socket] Connection error:', error);
          this.emit('error', error);
        };

        this.ws.onclose = (event) => {
          console.log('[Socket] Connection closed');
          this.isConnected = false;
          this.emit('disconnected');

          // Attempt reconnection only if not intentional and not max attempts
          if (!this.intentionalDisconnect && !event.wasClean && this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            console.log(`[Socket] Reconnecting... (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
            setTimeout(() => {
              this.connect().catch(err => {
                console.error('[Socket] Reconnection failed:', err);
              });
            }, this.reconnectDelay);
          }
        };

        // Connection timeout
        setTimeout(() => {
          if (!this.isConnected) {
            reject(new Error('Connection timeout'));
          }
        }, 10000);

      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Handle incoming message
   * @param {Object} message - Parsed message object
   */
  handleMessage(message) {
    const handler = this.messageHandlers.get(message.type);
    if (handler) {
      handler(message);
    } else {
      console.warn('[Socket] No handler for message type:', message.type);
    }
  }

  /**
   * Register message handler
   * @param {string} type - Message type
   * @param {Function} handler - Handler function
   */
  on(type, handler) {
    this.messageHandlers.set(type, handler);
  }

  /**
   * Emit event to handlers
   * @param {string} event - Event name
   * @param {*} data - Event data
   */
  emit(event, data) {
    const handler = this.messageHandlers.get(event);
    if (handler) {
      handler(data);
    }
  }

  /**
   * Send message to server
   * @param {Object} message - Message object
   */
  send(message) {
    if (!this.isConnected || !this.ws) {
      throw new Error('Not connected to server');
    }

    try {
      this.ws.send(JSON.stringify(message));
    } catch (error) {
      console.error('[Socket] Error sending message:', error);
      throw error;
    }
  }

  /**
   * Join session
   * @param {string} sessionId - Hashed session code
   * @param {string} salt - Session salt
   */
  joinSession(sessionId, salt) {
    this.send({
      type: 'join',
      sessionId: sessionId,
      salt: salt
    });
  }

  /**
   * Send encrypted message
   * @param {string} iv - Hex-encoded IV
   * @param {string} ciphertext - Hex-encoded ciphertext
   */
  sendEncryptedMessage(iv, ciphertext) {
    this.send({
      type: 'encrypted_message',
      iv: iv,
      ciphertext: ciphertext
    });
  }

  /**
   * Send encrypted file metadata
   * @param {string} fileId - Unique file identifier
   * @param {string} iv - Hex-encoded IV
   * @param {string} encryptedMetadata - Hex-encoded encrypted metadata
   * @param {number} totalChunks - Total number of chunks
   */
  sendEncryptedFile(fileId, iv, encryptedMetadata, totalChunks) {
    this.send({
      type: 'encrypted_file',
      fileId: fileId,
      iv: iv,
      encryptedMetadata: encryptedMetadata,
      totalChunks: totalChunks
    });
  }

  /**
   * Send encrypted file chunk
   * @param {string} fileId - Unique file identifier
   * @param {number} chunkIndex - Chunk index
   * @param {string} iv - Hex-encoded IV
   * @param {string} encryptedChunk - Hex-encoded encrypted chunk
   */
  sendEncryptedFileChunk(fileId, chunkIndex, iv, encryptedChunk) {
    this.send({
      type: 'encrypted_file_chunk',
      fileId: fileId,
      chunkIndex: chunkIndex,
      iv: iv,
      encryptedChunk: encryptedChunk
    });
  }

  /**
   * Send typing indicator
   * @param {boolean} isTyping - Whether user is typing
   */
  sendTypingIndicator(isTyping) {
    this.send({
      type: 'typing',
      isTyping: isTyping
    });
  }

  /**
   * Disconnect from server
   */
  disconnect() {
    if (this.ws) {
      this.intentionalDisconnect = true; // Mark as intentional
      this.ws.close(1000, 'User disconnected');
      this.ws = null;
      this.isConnected = false;
    }
  }

  /**
   * Check connection status
   * @returns {boolean}
   */
  isSocketConnected() {
    return this.isConnected && this.ws && this.ws.readyState === WebSocket.OPEN;
  }
}

// Export singleton instance
const socketManager = new SocketManager();
export default socketManager;
