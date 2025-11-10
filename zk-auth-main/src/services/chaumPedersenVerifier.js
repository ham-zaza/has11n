// src/services/chaumPedersenVerifier.js
import { createHash } from 'crypto';
import { ZKP_PARAMS } from '../config/zkpParams.js';
import modExp from '../utils/modExp.js';

/**
 * Non-Interactive Chaum-Pedersen ZKP Verifier (Fiat-Shamir)
 *
 * Computes c = H(g, h, y, z, a, b, domain, timestamp)
 * Rejects if timestamp is older than 5 minutes
 */

export function verifyChaumPedersen(proof, y, z) {
    const { p, q, g, h } = ZKP_PARAMS;
    const { a, b, s, domain, timestamp } = proof; // note: 's' instead of 'r'

    // 🔒 1. Validate timestamp (5-minute window)
    const now = Math.floor(Date.now() / 1000);
    if (timestamp < now - 300 || timestamp > now + 30) {
        console.log("❌ Proof failed: timestamp out of range");
        return false;
    }

    // 🔒 2. Validate domain (only allow localhost for demo)
    if (!domain) {
        console.log("❌ Proof failed: missing domain");
        return false;
    }

    // Allow both localhost and Chrome extensions
    if (!domain.startsWith('http://localhost') && !domain.startsWith('chrome-extension://')) {
        console.log(`❌ Proof failed: invalid domain: ${domain}`);
        return false;
    }

    // 🔢 3. Validate ranges
    if (a <= 0n || a >= p || b <= 0n || b >= p) return false;
    if (s < 0n || s >= q) return false;

    // 🔁 4. Compute c = H(g, h, y, z, a, b, domain, timestamp)
    const hash = createHash('sha256')
        .update(g.toString())
        .update(h.toString())
        .update(y.toString())
        .update(z.toString())
        .update(a.toString())
        .update(b.toString())
        .update(domain)
        .update(timestamp.toString())
        .digest(); // ← This returns a Buffer

    const c = BigInt('0x' + hash.toString('hex')) % q;

    // 🔢 5. Verify equations
    const left1 = modExp(g, s, p);
    const right1 = (a * modExp(y, c, p)) % p;

    const left2 = modExp(h, s, p);
    const right2 = (b * modExp(z, c, p)) % p;

    const valid = (left1 === right1) && (left2 === right2);
    if (valid) console.log("✅ Non-interactive ZKP VERIFIED!");
    else console.log("❌ ZKP verification failed");
    return valid;
}