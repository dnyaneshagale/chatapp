/**
 * Main Application Logic
 * 
 * Orchestrates UI, crypto, and socket modules
 * Handles user interactions and message flow
 */

import cryptoManager from './crypto.js';
import socketManager from './socket.js';

class ChatApp {
  constructor() {
    this.currentSessionCode = null;
    this.sessionId = null;
    this.peerConnected = false;
    this.typingTimeout = null;
    this.fileChunks = new Map(); // Store incoming file chunks
    
    this.initializeElements();
    this.initializeEventListeners();
    this.initializeSocketHandlers();
  }

  initializeElements() {
    // Join screen elements
    this.joinScreen = document.getElementById('join-screen');
    this.sessionCodeInput = document.getElementById('session-code');
    this.joinBtn = document.getElementById('join-btn');
    this.joinError = document.getElementById('join-error');

    // Chat screen elements
    this.chatScreen = document.getElementById('chat-screen');
    this.sessionInfo = document.getElementById('session-info');
    this.peerStatus = document.getElementById('peer-status');
    this.messagesContainer = document.getElementById('messages');
    this.messageInput = document.getElementById('message-input');
    this.sendBtn = document.getElementById('send-btn');
    this.fileInput = document.getElementById('file-input');
    this.fileBtn = document.getElementById('file-btn');
    this.leaveBtn = document.getElementById('leave-btn');
    this.typingIndicator = document.getElementById('typing-indicator');
  }

  initializeEventListeners() {
    // Join button
    this.joinBtn.addEventListener('click', () => this.joinSession());
    this.sessionCodeInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') this.joinSession();
    });

    // Send message button
    this.sendBtn.addEventListener('click', () => this.sendMessage());
    this.messageInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        this.sendMessage();
      }
    });

    // Typing indicator
    this.messageInput.addEventListener('input', () => {
      this.handleTyping();
    });

    // File button
    this.fileBtn.addEventListener('click', () => {
      this.fileInput.click();
    });
    this.fileInput.addEventListener('change', (e) => {
      if (e.target.files.length > 0) {
        this.sendFile(e.target.files[0]);
      }
    });

    // Leave button
    this.leaveBtn.addEventListener('click', () => this.leaveSession());

    // Prevent accidental page close
    window.addEventListener('beforeunload', (e) => {
      if (this.peerConnected) {
        e.preventDefault();
        e.returnValue = '';
      }
    });
  }

  initializeSocketHandlers() {
    // Connection handlers
    socketManager.on('connected', () => {
      console.log('[App] Socket connected');
    });

    socketManager.on('disconnected', () => {
      console.log('[App] Socket disconnected');
      this.showError('Disconnected from server. Attempting to reconnect...');
    });

    socketManager.on('error', (error) => {
      console.error('[App] Socket error:', error);
      this.showError('Connection error. Please try again.');
    });

    // Session handlers
    socketManager.on('joined', (data) => {
      console.log('[App] Joined session', data);
      this.handleJoinSuccess(data);
    });

    socketManager.on('peer_connected', () => {
      console.log('[App] Peer connected');
      this.peerConnected = true;
      this.updatePeerStatus(true);
    });

    socketManager.on('peer_disconnected', () => {
      console.log('[App] Peer disconnected');
      this.peerConnected = false;
      this.updatePeerStatus(false);
      this.addSystemMessage('Your peer has disconnected.');
    });

    // Message handlers
    socketManager.on('encrypted_message', async (data) => {
      await this.handleIncomingMessage(data);
    });

    socketManager.on('encrypted_file', async (data) => {
      await this.handleIncomingFileMetadata(data);
    });

    socketManager.on('encrypted_file_chunk', async (data) => {
      await this.handleIncomingFileChunk(data);
    });

    socketManager.on('typing', (data) => {
      this.showTypingIndicator(data.isTyping);
    });

    // Error handler
    socketManager.on('error', (data) => {
      this.showError(data.message);
    });
  }

  async joinSession() {
    const sessionCode = this.sessionCodeInput.value.trim();

    if (!sessionCode) {
      this.showJoinError('Please enter a session code');
      return;
    }

    if (sessionCode.length < 8) {
      this.showJoinError('Session code must be at least 8 characters');
      return;
    }

    try {
      this.joinBtn.disabled = true;
      this.joinBtn.textContent = 'Connecting...';
      this.joinError.textContent = '';

      // Connect to WebSocket server
      await socketManager.connect();

      // Generate or use salt
      const salt = cryptoManager.generateSalt();

      // Derive encryption key from session code
      await cryptoManager.deriveKey(sessionCode, salt);

      // Hash session code for server identification
      const sessionId = await cryptoManager.hashSessionCode(sessionCode);

      // Join session on server
      socketManager.joinSession(sessionId, salt);

      // Store session info
      this.currentSessionCode = sessionCode;
      this.sessionId = sessionId;

    } catch (error) {
      console.error('[App] Error joining session:', error);
      this.showJoinError('Failed to join session. Please try again.');
      this.joinBtn.disabled = false;
      this.joinBtn.textContent = 'Join Session';
    }
  }

  handleJoinSuccess(data) {
    console.log('[App] Join success:', data);

    // If salt from server is different, re-derive key with server's salt
    if (data.salt !== cryptoManager.sessionSalt) {
      cryptoManager.deriveKey(this.currentSessionCode, data.salt)
        .then(() => {
          console.log('[App] Key re-derived with server salt');
        })
        .catch(error => {
          console.error('[App] Error re-deriving key:', error);
        });
    }

    // Update peer status
    if (data.userCount === 2) {
      this.peerConnected = true;
    }

    // Switch to chat screen
    this.showChatScreen();
    this.updatePeerStatus(this.peerConnected);
    this.sessionInfo.textContent = `Session: ${this.sessionId.substring(0, 12)}...`;

    // Add welcome message
    this.addSystemMessage('Connected to secure session. Your messages are end-to-end encrypted.');
    if (!this.peerConnected) {
      this.addSystemMessage('Waiting for peer to join...');
    }
  }

  async sendMessage() {
    const message = this.messageInput.value.trim();

    if (!message) return;

    if (!cryptoManager.isKeyInitialized()) {
      this.showError('Encryption key not initialized');
      return;
    }

    if (!socketManager.isSocketConnected()) {
      this.showError('Not connected to server');
      return;
    }

    try {
      // Encrypt message
      const { iv, ciphertext } = await cryptoManager.encryptMessage(message);

      // Send encrypted message
      socketManager.sendEncryptedMessage(iv, ciphertext);

      // Display message locally
      this.addMessage(message, true);

      // Clear input
      this.messageInput.value = '';
      this.messageInput.focus();

      // Stop typing indicator
      socketManager.sendTypingIndicator(false);

    } catch (error) {
      console.error('[App] Error sending message:', error);
      this.showError('Failed to send message');
    }
  }

  async handleIncomingMessage(data) {
    try {
      // Decrypt message
      const plaintext = await cryptoManager.decryptMessage(data.iv, data.ciphertext);

      // Display message
      this.addMessage(plaintext, false);

    } catch (error) {
      console.error('[App] Error handling incoming message:', error);
      this.addSystemMessage('Failed to decrypt message (wrong session code?)');
    }
  }

  async sendFile(file) {
    // Validate file size (max 10MB)
    const MAX_FILE_SIZE = 10 * 1024 * 1024;
    if (file.size > MAX_FILE_SIZE) {
      this.showError('File too large. Maximum size is 10MB.');
      return;
    }

    if (!cryptoManager.isKeyInitialized()) {
      this.showError('Encryption key not initialized');
      return;
    }

    if (!socketManager.isSocketConnected()) {
      this.showError('Not connected to server');
      return;
    }

    try {
      this.addSystemMessage(`Sending file: ${file.name} (${this.formatFileSize(file.size)})`);

      // Generate unique file ID
      const fileId = this.generateFileId();

      // Read file as ArrayBuffer
      const fileData = await this.readFileAsArrayBuffer(file);

      // Encrypt file
      const { iv: fileIV, encryptedData } = await cryptoManager.encryptFile(fileData);

      // Encrypt metadata (filename, size, type, and file IV for decryption)
      const metadata = JSON.stringify({
        name: file.name,
        size: file.size,
        type: file.type,
        fileIV: fileIV  // Include file encryption IV so receiver can decrypt
      });
      const { iv: metadataIV, ciphertext: encryptedMetadata } = await cryptoManager.encryptMessage(metadata);

      // Split encrypted file into chunks (64KB)
      const CHUNK_SIZE = 64 * 1024;
      const chunks = this.splitIntoChunks(new Uint8Array(encryptedData), CHUNK_SIZE);

      // Send file metadata
      socketManager.sendEncryptedFile(fileId, metadataIV, encryptedMetadata, chunks.length);

      // Send chunks
      for (let i = 0; i < chunks.length; i++) {
        const chunkIV = cryptoManager.generateIV();
        const chunkHex = cryptoManager.bufferToHex(chunks[i]);
        
        socketManager.sendEncryptedFileChunk(fileId, i, cryptoManager.bufferToHex(chunkIV), chunkHex);
        
        // Small delay between chunks to avoid overwhelming the connection
        if (i < chunks.length - 1) {
          await this.sleep(10);
        }
      }

      // Create blob from decrypted data for local preview
      const blob = new Blob([fileData], { type: file.type });
      const url = URL.createObjectURL(blob);
      
      // Display sent file locally
      this.addFileMessage(file.name, url, file.size, file.type, true);

    } catch (error) {
      console.error('[App] Error sending file:', error);
      this.showError('Failed to send file');
    } finally {
      this.fileInput.value = '';
    }
  }

  async handleIncomingFileMetadata(data) {
    try {
      // Decrypt metadata
      const metadataJSON = await cryptoManager.decryptMessage(data.iv, data.encryptedMetadata);
      const metadata = JSON.parse(metadataJSON);

      // Initialize file chunk storage
      this.fileChunks.set(data.fileId, {
        metadata: metadata,
        fileIV: metadata.fileIV,  // Store file encryption IV for later decryption
        chunks: new Array(data.totalChunks),
        receivedCount: 0,
        totalChunks: data.totalChunks
      });

      this.addSystemMessage(`Receiving file: ${metadata.name} (${this.formatFileSize(metadata.size)})`);

    } catch (error) {
      console.error('[App] Error handling file metadata:', error);
      this.addSystemMessage('Failed to decrypt file metadata');
    }
  }

  async handleIncomingFileChunk(data) {
    try {
      const fileInfo = this.fileChunks.get(data.fileId);
      if (!fileInfo) {
        console.error('[App] No file info for chunk');
        return;
      }

      // Store chunk
      fileInfo.chunks[data.chunkIndex] = cryptoManager.hexToBuffer(data.encryptedChunk);
      fileInfo.receivedCount++;

      // Check if all chunks received
      if (fileInfo.receivedCount === fileInfo.totalChunks) {
        await this.reassembleFile(data.fileId, fileInfo);
      }

    } catch (error) {
      console.error('[App] Error handling file chunk:', error);
    }
  }

  async reassembleFile(fileId, fileInfo) {
    try {
      // Concatenate all chunks
      const totalSize = fileInfo.chunks.reduce((sum, chunk) => sum + chunk.length, 0);
      const encryptedFile = new Uint8Array(totalSize);
      let offset = 0;
      
      for (const chunk of fileInfo.chunks) {
        encryptedFile.set(chunk, offset);
        offset += chunk.length;
      }

      // Decrypt the reassembled file using the stored IV
      const decryptedData = await cryptoManager.decryptFile(fileInfo.fileIV, encryptedFile.buffer);

      // Create blob from decrypted data
      const blob = new Blob([decryptedData], { type: fileInfo.metadata.type });

      // Create viewable URL
      const url = URL.createObjectURL(blob);
      this.addFileMessage(fileInfo.metadata.name, url, fileInfo.metadata.size, fileInfo.metadata.type, false);

      // Cleanup
      this.fileChunks.delete(fileId);

    } catch (error) {
      console.error('[App] Error reassembling file:', error);
      this.addSystemMessage('Failed to reassemble file');
    }
  }

  handleTyping() {
    if (!this.peerConnected) return;

    // Send typing indicator
    socketManager.sendTypingIndicator(true);

    // Clear existing timeout
    if (this.typingTimeout) {
      clearTimeout(this.typingTimeout);
    }

    // Stop typing indicator after 2 seconds of inactivity
    this.typingTimeout = setTimeout(() => {
      socketManager.sendTypingIndicator(false);
    }, 2000);
  }

  showTypingIndicator(isTyping) {
    if (isTyping) {
      this.typingIndicator.classList.add('visible');
    } else {
      this.typingIndicator.classList.remove('visible');
    }
  }

  leaveSession() {
    if (confirm('Are you sure you want to leave this session?')) {
      // Clear encryption key from memory
      cryptoManager.clearKey();

      // Disconnect from server
      socketManager.disconnect();

      // Reset state
      this.currentSessionCode = null;
      this.sessionId = null;
      this.peerConnected = false;
      this.fileChunks.clear();

      // Clear messages
      this.messagesContainer.innerHTML = '';

      // Reset form
      this.sessionCodeInput.value = '';
      this.messageInput.value = '';
      this.joinBtn.disabled = false;
      this.joinBtn.textContent = 'Join Session';

      // Show join screen
      this.showJoinScreen();
    }
  }

  // UI Helper Methods

  showJoinScreen() {
    this.joinScreen.classList.remove('hidden');
    this.chatScreen.classList.add('hidden');
    this.sessionCodeInput.focus();
  }

  showChatScreen() {
    this.joinScreen.classList.add('hidden');
    this.chatScreen.classList.remove('hidden');
    this.messageInput.focus();
  }

  showJoinError(message) {
    this.joinError.textContent = message;
  }

  showError(message) {
    this.addSystemMessage(`Error: ${message}`);
  }

  updatePeerStatus(connected) {
    if (connected) {
      this.peerStatus.textContent = 'Peer: Connected';
      this.peerStatus.classList.add('connected');
      this.peerStatus.classList.remove('disconnected');
    } else {
      this.peerStatus.textContent = 'Peer: Waiting...';
      this.peerStatus.classList.add('disconnected');
      this.peerStatus.classList.remove('connected');
    }
  }

  addMessage(text, isSent) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${isSent ? 'sent' : 'received'}`;
    
    const textDiv = document.createElement('div');
    textDiv.className = 'message-text';
    textDiv.textContent = text;
    
    const timeDiv = document.createElement('div');
    timeDiv.className = 'message-time';
    timeDiv.textContent = this.formatTime(new Date());
    
    messageDiv.appendChild(textDiv);
    messageDiv.appendChild(timeDiv);
    
    this.messagesContainer.appendChild(messageDiv);
    this.scrollToBottom();
  }

  addFileMessage(filename, url, size, fileType, isSent) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${isSent ? 'sent' : 'received'}`;
    
    // Check if file is an image
    const isImage = fileType && fileType.startsWith('image/');
    
    if (isImage) {
      messageDiv.classList.add('has-image');
      
      // Display image inline
      const imgContainer = document.createElement('div');
      imgContainer.className = 'message-image-container';
      
      const img = document.createElement('img');
      img.src = url;
      img.className = 'message-image';
      img.alt = filename;
      img.onclick = () => window.open(url, '_blank');
      
      const caption = document.createElement('div');
      caption.className = 'message-image-caption';
      caption.textContent = `${filename} (${this.formatFileSize(size)})`;
      
      imgContainer.appendChild(img);
      imgContainer.appendChild(caption);
      messageDiv.appendChild(imgContainer);
    } else {
      // Display file info with view option
      const fileDiv = document.createElement('div');
      fileDiv.className = 'message-file';
      
      const icon = document.createElement('span');
      icon.className = 'file-icon';
      icon.textContent = this.getFileIcon(fileType);
      
      const fileInfo = document.createElement('div');
      fileInfo.className = 'file-info';
      
      const fileName = document.createElement('div');
      fileName.className = 'file-name';
      fileName.textContent = filename;
      
      const fileSize = document.createElement('div');
      fileSize.className = 'file-size';
      fileSize.textContent = this.formatFileSize(size);
      
      const viewBtn = document.createElement('button');
      viewBtn.className = 'file-view-btn';
      viewBtn.textContent = 'View';
      viewBtn.onclick = () => window.open(url, '_blank');
      
      fileInfo.appendChild(fileName);
      fileInfo.appendChild(fileSize);
      fileDiv.appendChild(icon);
      fileDiv.appendChild(fileInfo);
      fileDiv.appendChild(viewBtn);
      messageDiv.appendChild(fileDiv);
    }
    
    const timeDiv = document.createElement('div');
    timeDiv.className = 'message-time';
    timeDiv.textContent = this.formatTime(new Date());
    
    messageDiv.appendChild(timeDiv);
    
    this.messagesContainer.appendChild(messageDiv);
    this.scrollToBottom();
  }

  addSystemMessage(text) {
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message system';
    messageDiv.textContent = text;
    
    this.messagesContainer.appendChild(messageDiv);
    this.scrollToBottom();
  }

  scrollToBottom() {
    this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
  }

  // Utility Methods

  formatTime(date) {
    return date.toLocaleTimeString('en-US', { 
      hour: '2-digit', 
      minute: '2-digit' 
    });
  }

  formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  }

  getFileIcon(fileType) {
    if (!fileType) return '📄';
    if (fileType.startsWith('image/')) return '🖼️';
    if (fileType.startsWith('video/')) return '🎥';
    if (fileType.startsWith('audio/')) return '🎵';
    if (fileType.includes('pdf')) return '📕';
    if (fileType.includes('word') || fileType.includes('document')) return '📘';
    if (fileType.includes('sheet') || fileType.includes('excel')) return '📗';
    if (fileType.includes('zip') || fileType.includes('compressed')) return '📦';
    if (fileType.includes('text')) return '📝';
    return '📄';
  }

  generateFileId() {
    return Date.now() + '-' + Math.random().toString(36).substring(2);
  }

  readFileAsArrayBuffer(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = reject;
      reader.readAsArrayBuffer(file);
    });
  }

  splitIntoChunks(data, chunkSize) {
    const chunks = [];
    for (let i = 0; i < data.length; i += chunkSize) {
      chunks.push(data.slice(i, i + chunkSize));
    }
    return chunks;
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new ChatApp();
});
