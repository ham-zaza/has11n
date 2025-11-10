# 🧾 ZK-Auth — Changelog

A privacy-preserving passwordless authentication system using Zero-Knowledge Proofs (Chaum–Pedersen Protocol).

---

## [3.0.0] — 2025-10-30
### 🔒 Stage 3 Complete: Secure, Non-Interactive ZKP Login with Chrome Extension

> **Milestone**: Fully secure, **non-interactive**, **replay-resistant**, **phishing-resistant** passwordless login via Chrome extension — **FYP-ready for Modules 1–3**.

This release completes **Modules 1–3** of the Final Year Project:
- **Module 1**: Secure user registration with encrypted key storage
- **Module 2**: Non-interactive ZKP (Fiat–Shamir) with replay/phishing protection
- **Module 3**: Hardened Chrome extension with PIN unlock and auto-lock

---

### ✨ Added

- **Non-Interactive ZKP (Fiat–Shamir Transform)**:
    - Removed `/api/auth/challenge` endpoint
    - Proof now computed in **one round**: `c = H(g, h, y, z, a, b, domain, timestamp)`
    - Backend verifies proof **without prior interaction**
- **Replay & Phishing Protection**:
    - Proof includes **timestamp** (5-minute window)
    - Proof includes **domain** (`chrome-extension://...` or `http://localhost`)
    - Backend rejects proofs with expired timestamps or invalid domains
- **Secure Key Storage (Module 1)**:
    - Secret key `x` is **encrypted with AES-GCM** using a **PIN-derived key**
    - PIN → PBKDF2 (100,000 iterations) → AES-256-GCM key
    - Only encrypted `x` stored in `chrome.storage.local`
- **Chrome Extension Hardening (Module 3)**:
    - **6-digit PIN setup** on first use
    - **Auto-lock after 2 minutes** of inactivity
    - **Unlock screen** required before login/register
    - Secure random key generation using `crypto.getRandomValues()`
- **New Utilities**:
    - `src/utils/cryptoUtils.js` — AES-GCM + PBKDF2 helpers (extension-side)
    - `content.js` — content script for future auto-login detection
- **Updated UI**:
    - `popup.html` — PIN setup, lock screen, login form
    - Clear status messages for all operations

---

### 🛠 Changed

- **Backend**:
    - `authController.js`:
        - Replaced interactive ZKP with **non-interactive verifier**
        - Uses `import { createHash } from 'crypto'` (ESM-compliant)
        - Validates `domain` and `timestamp` in every proof
    - `chaumPedersenVerifier.js`:
        - Now computes `c` from full Fiat–Shamir hash
        - Rejects proofs outside 5-minute window
        - Logs detailed verification steps
    - `User.js`:
        - Renamed `publicKey` → `publicKeyY`
        - Made `publicKeyZ` **required**
- **Extension**:
    - `popup.js`:
        - Full secure flow: PIN → key generation → registration → login
        - Uses `chrome.runtime.getURL('')` for domain binding
        - Sends proof in **one request** to `/api/login`
    - `manifest.json`:
        - Added `content_scripts` for future website integration
        - Kept `host_permissions` for `localhost:3000`
- **Project Structure**:
    - Extension now has `src/utils/` and `src/config/` mirroring backend
    - Shared `zkpParams.js` ensures parameter consistency

---

### 🚫 Removed

- Interactive ZKP flow:
    - Deleted `/api/auth/challenge` route
    - Removed `getChallenge` controller
- Hardcoded secret key (`x = 12345n`)
- Plaintext storage of `secretX` in `chrome.storage.local`

---

### ✅ Verified

- ✅ **Registration**:
    - User sets 6-digit PIN
    - Generates **unique random `x`** per user
    - Computes `y = g^x mod p`, `z = h^x mod p`
    - Stores **encrypted `x`** in extension storage
- ✅ **Login**:
    - User unlocks with PIN
    - Computes **non-interactive ZKP proof** in one step
    - Proof includes **domain + timestamp**
    - Backend **verifies proof** → **✅ Login successful!**
- ✅ **Security**:
    - ❌ **No replay**: same proof fails after 5 minutes
    - ❌ **No phishing**: proof fails on wrong domain
    - ❌ **No key leakage**: `x` never leaves extension in plaintext
    - ❌ **No weak randomness**: uses `crypto.getRandomValues()`
- ✅ **Usability**:
    - Auto-lock after 2 minutes
    - Clear error messages (wrong PIN, invalid proof, etc.)
    - Works end-to-end: **Register → Unlock → Login**

---

### 🧪 Demo Commands (Copy-Paste for Supervisor Showcase)

> 💡 Run these to **reproduce your FYP demo**.

```bash
# 1. Start backend
cd "D:\Hamza uni stuff\fyp\zk-auth\phase 0"
npm start

# 2. Load extension in Chrome:
#    - Go to chrome://extensions
#    - Enable "Developer mode"
#    - Click "Load unpacked" → select `zkp-auth-extension` folder

# 3. Demo Flow:
#    a. Click extension → Set 6-digit PIN (e.g., 123456)
#    b. Enter username (e.g., hamza_fyp)
#    c. Click "Register" → ✅ Registered!
#    d. Close & reopen popup → Enter PIN → Unlock
#    e. Click "Login" → ✅ Login successful!

# 4. Security Tests:
#    - Wait 6 minutes → try login → ❌ "Proof timestamp expired"
#    - Try wrong PIN → ❌ "Wrong PIN"
#    - Check MongoDB → user has unique publicKeyY/publicKeyZ