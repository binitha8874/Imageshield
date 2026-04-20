# ⬡ ImageShield — Full Setup Guide

## What's Included

| File | Purpose |
|------|---------|
| `index.html` | Complete frontend — Landing page + Dashboard (single file) |
| `server.js` | Node.js/Express backend API |
| `package.json` | Dependencies |
| `.env.example` | Environment variable template |

---

## Quick Start (Frontend only — works immediately)

Just open `index.html` in any browser. The full UI works standalone with simulated data.

---

## Full Backend Setup

### 1. Install Node.js dependencies
```bash
npm install
```

### 2. Set up Firebase
1. Go to https://console.firebase.google.com → Create a project called `imageshield`
2. Enable **Firestore Database** (production mode)
3. Enable **Firebase Storage**
4. Enable **Firebase Authentication** (Email/Password + Phone)
5. Go to **Project Settings → Service accounts** → Generate new private key
6. Save as `serviceAccountKey.json` in the project root

### 3. Set up Gmail App Password (for OTP emails)
1. Enable 2FA on your Gmail account
2. Go to https://myaccount.google.com/apppasswords
3. Create an app password for "Mail"
4. Copy the 16-character password

### 4. Set up Twilio (for OTP SMS)
1. Sign up at https://console.twilio.com
2. Get a free phone number
3. Copy your Account SID, Auth Token, and Twilio phone number

### 5. Configure .env
```bash
cp .env.example .env
# Edit .env with your actual values
```

### 6. Run the server
```bash
npm run dev   # Development (auto-restart)
npm start     # Production
```

### 7. Deploy to Google Cloud Run (recommended)
```bash
# Install Google Cloud CLI: https://cloud.google.com/sdk/docs/install
gcloud init
gcloud run deploy imageshield \
  --source . \
  --platform managed \
  --region asia-south1 \
  --allow-unauthenticated
```

---

## Firestore Collections

| Collection | Purpose |
|------------|---------|
| `users` | Registered users (email, phone, passwordHash) |
| `images` | Registered images with licence keys & fingerprints |
| `fingerprints` | Global SHA-256 fingerprint registry |
| `licenceRequests` | Requests for restricted images |
| `violations` | Detected unauthorised uses |

---

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/send-otp` | No | Send OTP to email + phone |
| POST | `/api/auth/verify-otp` | No | Verify OTP + create account |
| POST | `/api/auth/login` | No | Log in, receive token |
| POST | `/api/images/register` | ✅ | Upload + register image |
| GET | `/api/images` | ✅ | List user's images |
| PATCH | `/api/images/:id/visibility` | ✅ | Change public/private/restricted |
| DELETE | `/api/images/:id` | ✅ | Remove image |
| GET | `/api/licence/verify/:key` | No | Verify a licence key (public) |
| POST | `/api/licence/request` | ✅ | Request access to restricted image |
| GET | `/api/violations` | ✅ | List violations for user's images |
| POST | `/api/violations` | ✅ | Report a violation |
| POST | `/api/dmca/generate` | ✅ | Generate DMCA notice |
| GET | `/api/stats` | ✅ | Dashboard statistics |

---

## Visibility Modes

| Mode | Who can view | Use case |
|------|-------------|---------|
| 🌐 **Public** | Everyone (with attribution) | Portfolio, open licensing |
| 🔒 **Private** | Owner only | Personal/unreleased work |
| 🛡️ **Restricted** | Approved parties only | Commercial, controlled distribution |

---

## Security Notes
- Passwords are SHA-256 hashed (use bcrypt in production)
- OTPs expire in 10 minutes
- Firebase Storage rules enforce private/restricted access
- All tokens are Firebase custom tokens (JWT)
- Image fingerprinting uses SHA-256 hash of raw buffer
