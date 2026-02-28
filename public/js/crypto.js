/**
 * Cryptography Module
 * 
 * Implements secure end-to-end encryption using Web Crypto API
 * 
 * SECURITY SPECIFICATIONS:
 * - Algorithm: AES-256-GCM (Galois/Counter Mode)
 * - Key Derivation: PBKDF2 with SHA-256
 * - Iterations: 150,000
 * - Salt: Random 16 bytes per session (shared between users)
 * - IV: Random 12 bytes per message
 * - Key Storage: NEVER stored in localStorage - kept in memory only
 */

class CryptoManager {
  constructor() {
    this.encryptionKey = null; // CryptoKey object - lives only in memory
    this.sessionSalt = null; // Hex string
  }

  /**
   * Generate random salt for key derivation
   * @returns {string} - 32-character hex string (16 bytes)
   */
  generateSalt() {
    const saltBuffer = new Uint8Array(16);
    crypto.getRandomValues(saltBuffer);
    return this.bufferToHex(saltBuffer);
  }

  /**
   * Generate random IV for encryption
   * @returns {Uint8Array} - 12 bytes
   */
  generateIV() {
    const iv = new Uint8Array(12);
    crypto.getRandomValues(iv);
    return iv;
  }

  /**
   * Derive encryption key from session code and salt using PBKDF2
   * 
   * SECURITY: Uses 150,000 iterations to make brute-force attacks expensive
   * 
   * @param {string} sessionCode - User's session code (passphrase)
   * @param {string} saltHex - Hex-encoded salt
   * @returns {Promise<CryptoKey>} - AES-GCM key
   */
  async deriveKey(sessionCode, saltHex) {
    try {
      // Convert session code to buffer
      const encoder = new TextEncoder();
      const passwordBuffer = encoder.encode(sessionCode);

      // Convert hex salt to buffer
      const saltBuffer = this.hexToBuffer(saltHex);

      // Import password as key material
      const keyMaterial = await crypto.subtle.importKey(
        'raw',
        passwordBuffer,
        'PBKDF2',
        false,
        ['deriveKey']
      );

      // Derive AES-GCM key using PBKDF2
      const key = await crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: saltBuffer,
          iterations: 150000, // SECURITY: High iteration count
          hash: 'SHA-256'
        },
        keyMaterial,
        {
          name: 'AES-GCM',
          length: 256 // SECURITY: 256-bit key
        },
        false, // SECURITY: Key is not extractable
        ['encrypt', 'decrypt']
      );

      // Store key and salt in memory only
      this.encryptionKey = key;
      this.sessionSalt = saltHex;

      return key;
    } catch (error) {
      console.error('[Crypto] Error deriving key:', error);
      throw new Error('Failed to derive encryption key');
    }
  }

  /**
   * Encrypt text message
   * 
   * @param {string} plaintext - Message to encrypt
   * @returns {Promise<Object>} - { iv: string, ciphertext: string }
   */
  async encryptMessage(plaintext) {
    if (!this.encryptionKey) {
      throw new Error('Encryption key not initialized');
    }

    try {
      // Generate random IV for this message
      const iv = this.generateIV();

      // Convert plaintext to buffer
      const encoder = new TextEncoder();
      const plaintextBuffer = encoder.encode(plaintext);

      // Encrypt using AES-GCM
      const ciphertextBuffer = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: iv,
          tagLength: 128 // SECURITY: 128-bit authentication tag
        },
        this.encryptionKey,
        plaintextBuffer
      );

      // Return IV and ciphertext as hex strings
      return {
        iv: this.bufferToHex(iv),
        ciphertext: this.bufferToHex(new Uint8Array(ciphertextBuffer))
      };
    } catch (error) {
      console.error('[Crypto] Error encrypting message:', error);
      throw new Error('Failed to encrypt message');
    }
  }

  /**
   * Decrypt text message
   * 
   * @param {string} ivHex - Hex-encoded IV
   * @param {string} ciphertextHex - Hex-encoded ciphertext
   * @returns {Promise<string>} - Decrypted plaintext
   */
  async decryptMessage(ivHex, ciphertextHex) {
    if (!this.encryptionKey) {
      throw new Error('Encryption key not initialized');
    }

    try {
      // Convert hex strings to buffers
      const iv = this.hexToBuffer(ivHex);
      const ciphertext = this.hexToBuffer(ciphertextHex);

      // Decrypt using AES-GCM
      const plaintextBuffer = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv,
          tagLength: 128
        },
        this.encryptionKey,
        ciphertext
      );

      // Convert buffer to string
      const decoder = new TextDecoder();
      return decoder.decode(plaintextBuffer);
    } catch (error) {
      console.error('[Crypto] Error decrypting message:', error);
      throw new Error('Failed to decrypt message - wrong key or corrupted data');
    }
  }

  /**
   * Encrypt file data
   * 
   * @param {ArrayBuffer} fileData - File data to encrypt
   * @returns {Promise<Object>} - { iv: string, encryptedData: ArrayBuffer }
   */
  async encryptFile(fileData) {
    if (!this.encryptionKey) {
      throw new Error('Encryption key not initialized');
    }

    try {
      // Generate random IV for this file
      const iv = this.generateIV();

      // Encrypt using AES-GCM
      const encryptedData = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: iv,
          tagLength: 128
        },
        this.encryptionKey,
        fileData
      );

      return {
        iv: this.bufferToHex(iv),
        encryptedData: encryptedData
      };
    } catch (error) {
      console.error('[Crypto] Error encrypting file:', error);
      throw new Error('Failed to encrypt file');
    }
  }

  /**
   * Decrypt file data
   * 
   * @param {string} ivHex - Hex-encoded IV
   * @param {ArrayBuffer} encryptedData - Encrypted file data
   * @returns {Promise<ArrayBuffer>} - Decrypted file data
   */
  async decryptFile(ivHex, encryptedData) {
    if (!this.encryptionKey) {
      throw new Error('Encryption key not initialized');
    }

    try {
      // Convert hex IV to buffer
      const iv = this.hexToBuffer(ivHex);

      // Decrypt using AES-GCM
      const decryptedData = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv,
          tagLength: 128
        },
        this.encryptionKey,
        encryptedData
      );

      return decryptedData;
    } catch (error) {
      console.error('[Crypto] Error decrypting file:', error);
      throw new Error('Failed to decrypt file - wrong key or corrupted data');
    }
  }

  /**
   * Hash session code for server identification
   * SECURITY: Server never sees the actual session code
   * 
   * @param {string} sessionCode - User's session code
   * @returns {Promise<string>} - Hex-encoded hash
   */
  async hashSessionCode(sessionCode) {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(sessionCode);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      return this.bufferToHex(new Uint8Array(hashBuffer));
    } catch (error) {
      console.error('[Crypto] Error hashing session code:', error);
      throw new Error('Failed to hash session code');
    }
  }

  /**
   * Convert ArrayBuffer/Uint8Array to hex string
   * @param {Uint8Array} buffer - Buffer to convert
   * @returns {string} - Hex string
   */
  bufferToHex(buffer) {
    return Array.from(buffer)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Convert hex string to Uint8Array
   * @param {string} hex - Hex string
   * @returns {Uint8Array} - Buffer
   */
  hexToBuffer(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  /**
   * Clear encryption key from memory
   * SECURITY: Called when leaving session
   */
  clearKey() {
    this.encryptionKey = null;
    this.sessionSalt = null;
  }

  /**
   * Check if key is initialized
   * @returns {boolean}
   */
  isKeyInitialized() {
    return this.encryptionKey !== null;
  }
}

// Export singleton instance
const cryptoManager = new CryptoManager();
export default cryptoManager;
