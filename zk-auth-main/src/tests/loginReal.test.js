// src/tests/loginReal.test.js
import fetch from 'node-fetch';
import { ZKP_PARAMS } from '../config/zkpParams.js';
import modExp from '../utils/modExp.js';
import { randomBytes } from 'crypto';

const { p, q, g, h } = ZKP_PARAMS;

// 🔑 MUST match your registered user!
const USERNAME = "zkp_user_1762648929114";
const SECRET_X = 12345n; // ← same as in chaumPedersenVerifier.test.js

async function zkpLogin() {
    try {
        console.log("🔐 Starting REAL ZKP Login...");

        // Generate random k using Node.js crypto
        const array = randomBytes(32);
        const k = BigInt('0x' + Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('')) % q;

        // Compute public keys y, z
        const y = modExp(g, SECRET_X, p);
        const z = modExp(h, SECRET_X, p);

        // Compute commitment a = g^k, b = h^k
        const a = modExp(g, k, p);
        const b = modExp(h, k, p);

        // Fiat-Shamir: c = H(g, h, y, z, a, b, domain, timestamp)
        const domain = 'http://localhost:3000';
        const timestamp = Math.floor(Date.now() / 1000).toString();

        const encoder = new TextEncoder();
        const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(
            g.toString() +
            h.toString() +
            y.toString() +
            z.toString() +
            a.toString() +
            b.toString() +
            domain +
            timestamp
        ));
        const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
        const c = BigInt('0x' + hashHex) % q;

        // Response s = k + c * x mod q
        const s = (k + c * SECRET_X) % q;

        console.log("📊 Proof Details:");
        console.log("a =", a.toString());
        console.log("b =", b.toString());
        console.log("c =", c.toString());
        console.log("s =", s.toString());

        // Send login request with proof
        const res = await fetch('http://localhost:3000/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: USERNAME,
                a: a.toString(),
                b: b.toString(),
                s: s.toString(),
                domain,
                timestamp
            })
        });

        if (res.ok) {
            console.log("✅ Login successful!");
        } else {
            const err = await res.json();
            console.log("❌ Login failed:", err.error || 'Unknown error');
        }
    } catch (err) {
        console.error("💥 Login failed:", err.message);
    }
}

zkpLogin();
