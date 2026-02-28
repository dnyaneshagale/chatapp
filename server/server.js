/**
 * Secure E2E Encrypted Chat Server
 * 
 * SECURITY NOTES:
 * - Server NEVER sees plaintext messages
 * - All encryption/decryption happens client-side
 * - Server only relays encrypted JSON blobs
 * - No sensitive data is logged
 * - Sessions auto-destroy when empty
 */

import express from 'express';
import { WebSocketServer } from 'ws';
import { createServer } from 'http';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import dotenv from 'dotenv';
import SessionManager from './sessionManager.js';
import RateLimiter from './rateLimiter.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const PORT = process.env.PORT || 3000;
const app = express();
const server = createServer(app);
const wss = new WebSocketServer({ server });

// Initialize managers
const sessionManager = new SessionManager();
const rateLimiter = new RateLimiter();

// Serve static files from public directory
app.use(express.static(join(__dirname, '../public')));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    activeSessions: sessionManager.getActiveSessionsCount(),
    timestamp: Date.now()
  });
});

// WebSocket connection handler
wss.on('connection', (ws, req) => {
  const clientIp = req.socket.remoteAddress;
  let currentSessionId = null;
  const connectionId = `${clientIp}-${Date.now()}-${Math.random()}`;

  console.log(`[WebSocket] New connection from ${clientIp}`);

  ws.on('message', (data) => {
    try {
      // Rate limit check
      if (!rateLimiter.checkLimit(connectionId, 'message')) {
        ws.send(JSON.stringify({
          type: 'error',
          message: 'Rate limit exceeded. Please slow down.'
        }));
        return;
      }

      const message = JSON.parse(data);

      switch (message.type) {
        case 'join':
          handleJoin(ws, message);
          break;

        case 'encrypted_message':
          handleEncryptedMessage(ws, message);
          break;

        case 'encrypted_file':
          handleEncryptedFile(ws, message);
          break;

        case 'encrypted_file_chunk':
          handleEncryptedFileChunk(ws, message);
          break;

        case 'typing':
          handleTyping(ws, message);
          break;

        default:
          ws.send(JSON.stringify({
            type: 'error',
            message: 'Unknown message type'
          }));
      }
    } catch (error) {
      console.error('[WebSocket] Error processing message:', error.message);
      ws.send(JSON.stringify({
        type: 'error',
        message: 'Invalid message format'
      }));
    }
  });

  ws.on('close', () => {
    console.log(`[WebSocket] Connection closed from ${clientIp}`);
    if (currentSessionId) {
      sessionManager.leaveSession(currentSessionId, ws);
      
      // Notify other user that peer disconnected
      sessionManager.broadcastToSession(currentSessionId, ws, {
        type: 'peer_disconnected'
      });
    }
    rateLimiter.reset(connectionId);
  });

  ws.on('error', (error) => {
    console.error('[WebSocket] Connection error:', error.message);
  });

  /**
   * Handle join session request
   * SECURITY: sessionId is a hash of the session code, not the code itself
   */
  function handleJoin(ws, message) {
    const { sessionId, salt } = message;

    if (!sessionId || !salt) {
      ws.send(JSON.stringify({
        type: 'error',
        message: 'Missing sessionId or salt'
      }));
      return;
    }

    // Validate salt format (should be hex string)
    if (!/^[a-f0-9]{32}$/.test(salt)) {
      ws.send(JSON.stringify({
        type: 'error',
        message: 'Invalid salt format'
      }));
      return;
    }

    // Join session
    const result = sessionManager.joinSession(sessionId, salt, ws);

    if (!result.success) {
      ws.send(JSON.stringify({
        type: 'error',
        message: result.error
      }));
      return;
    }

    currentSessionId = sessionId;

    // Send join success with salt
    ws.send(JSON.stringify({
      type: 'joined',
      userCount: result.userCount,
      salt: result.salt
    }));

    console.log(`[Session] User joined session ${sessionId.substring(0, 8)}... (${result.userCount}/2)`);

    // Notify other user that peer connected
    if (result.userCount === 2) {
      sessionManager.broadcastToSession(currentSessionId, ws, {
        type: 'peer_connected'
      });
    }
  }

  /**
   * Handle encrypted message relay
   * SECURITY: Server never decrypts - just relays encrypted blob
   */
  function handleEncryptedMessage(ws, message) {
    if (!currentSessionId) {
      ws.send(JSON.stringify({
        type: 'error',
        message: 'Not in a session'
      }));
      return;
    }

    // Validate encrypted message structure
    if (!message.iv || !message.ciphertext) {
      ws.send(JSON.stringify({
        type: 'error',
        message: 'Invalid encrypted message format'
      }));
      return;
    }

    // Relay encrypted message to other user
    sessionManager.broadcastToSession(currentSessionId, ws, {
      type: 'encrypted_message',
      iv: message.iv,
      ciphertext: message.ciphertext,
      timestamp: Date.now()
    });
  }

  /**
   * Handle encrypted file metadata relay
   * SECURITY: Server never decrypts - metadata is encrypted
   */
  function handleEncryptedFile(ws, message) {
    if (!currentSessionId) {
      ws.send(JSON.stringify({
        type: 'error',
        message: 'Not in a session'
      }));
      return;
    }

    // Validate encrypted file structure
    if (!message.iv || !message.encryptedMetadata || !message.fileId) {
      ws.send(JSON.stringify({
        type: 'error',
        message: 'Invalid encrypted file format'
      }));
      return;
    }

    // Relay encrypted file metadata to other user
    sessionManager.broadcastToSession(currentSessionId, ws, {
      type: 'encrypted_file',
      fileId: message.fileId,
      iv: message.iv,
      encryptedMetadata: message.encryptedMetadata,
      totalChunks: message.totalChunks,
      timestamp: Date.now()
    });
  }

  /**
   * Handle encrypted file chunk relay
   * SECURITY: Chunks are encrypted
   */
  function handleEncryptedFileChunk(ws, message) {
    if (!currentSessionId) {
      ws.send(JSON.stringify({
        type: 'error',
        message: 'Not in a session'
      }));
      return;
    }

    // Validate encrypted chunk structure (chunkIndex can be 0, so check for undefined/null)
    if (!message.fileId || message.chunkIndex === undefined || message.chunkIndex === null || !message.iv || !message.encryptedChunk) {
      ws.send(JSON.stringify({
        type: 'error',
        message: 'Invalid encrypted chunk format'
      }));
      return;
    }

    // Relay encrypted chunk to other user
    sessionManager.broadcastToSession(currentSessionId, ws, {
      type: 'encrypted_file_chunk',
      fileId: message.fileId,
      chunkIndex: message.chunkIndex,
      iv: message.iv,
      encryptedChunk: message.encryptedChunk
    });
  }

  /**
   * Handle typing indicator relay
   */
  function handleTyping(ws, message) {
    if (!currentSessionId) return;

    sessionManager.broadcastToSession(currentSessionId, ws, {
      type: 'typing',
      isTyping: message.isTyping
    });
  }
});

// Cleanup job - runs every 5 minutes
setInterval(() => {
  sessionManager.cleanupStaleSessions();
  rateLimiter.cleanup();
}, 5 * 60 * 1000);

// Start server
server.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════╗
║   Secure E2E Encrypted Chat Server        ║
║   Running on http://localhost:${PORT}       ║
║                                            ║
║   🔒 End-to-End Encrypted                 ║
║   👥 2-Person Sessions                    ║
║   🚀 Production Ready                     ║
╚════════════════════════════════════════════╝
  `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('[Server] SIGTERM received, closing server...');
  server.close(() => {
    console.log('[Server] Server closed');
    process.exit(0);
  });
});
