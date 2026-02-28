# 🔒 DNA Chat - E2E Encrypted

Secure end-to-end encrypted 2-person chat with file sharing.

## Features

- ✅ AES-256-GCM encryption (client-side only)
- ✅ PBKDF2 key derivation (150k iterations)
- ✅ 2-person sessions only
- ✅ File sharing up to 10MB (encrypted)
- ✅ Server cannot read messages
- ✅ No database - sessions auto-destroy

## Tech Stack

**Backend**: Node.js, Express, WebSocket (ws)  
**Frontend**: Vanilla HTML/CSS/JS, Web Crypto API  
**Security**: AES-256-GCM, PBKDF2, SHA-256

## Quick Start

```bash
# Install dependencies
cd server
npm install

# Start server
npm start
```

Open browser: `http://localhost:3000`

## How to Use

1. **Both users** enter the same session code (min 8 chars)
2. Click "Join Session"
3. Start chatting securely!

**File Sharing**: Click 📎 to send encrypted files

## Security

- **Encryption**: Client-side only (AES-256-GCM)
- **Keys**: Derived from session code, stored in memory only
- **IVs**: Random 12 bytes per message
- **Server**: Only relays encrypted data, cannot decrypt

## Project Structure

```
chatapp/
├── server/          # Node.js backend
│   ├── server.js
│   ├── sessionManager.js
│   ├── rateLimiter.js
│   └── package.json
└── public/          # Frontend
    ├── index.html
    ├── css/style.css
    └── js/
        ├── app.js       # Main app logic
        ├── crypto.js    # Encryption
        └── socket.js    # WebSocket
```

## Deploy to Render

1. Push to GitHub
2. Go to https://dashboard.render.com
3. New → Blueprint
4. Select your repo
5. Deploy!

(Uses `render.yaml` config)

## License

MIT
