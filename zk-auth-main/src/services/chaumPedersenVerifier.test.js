// src/services/chaumPedersenVerifier.test.js
import { verifyChaumPedersen } from './chaumPedersenVerifier.js';
import { ZKP_PARAMS } from '../config/zkpParams.js';
import modExp from '../utils/modExp.js';

// 🔑 Secret value (only user knows this)
const x = 12345n;

// 🔑 Generate TWO public keys (what server stores)
const y = modExp(ZKP_PARAMS.g, x, ZKP_PARAMS.p); // y = g^x mod p
const z = modExp(ZKP_PARAMS.h, x, ZKP_PARAMS.p); // z = h^x mod p

// 🎲 Simulate a valid proof (as if user generated it)
const k = 67890n; // random nonce (only user knows this temporarily)

const a = modExp(ZKP_PARAMS.g, k, ZKP_PARAMS.p); // a = g^k mod p
const b = modExp(ZKP_PARAMS.h, k, ZKP_PARAMS.p); // b = h^k mod p

const c = 999n; // challenge (in real flow, server sends this!)
const r = (k + c * x) % ZKP_PARAMS.q;            // r = k + c*x mod q

// 📦 Build the proof object
const fakeProof = { a, b, c, r };

console.log("📋 COPY-PASTE THESE INTO loginTest.js:");
console.log("a:", a.toString());
console.log("b:", b.toString());
console.log("c:", c.toString());
console.log("r:", r.toString());
console.log("username: 'YOUR_USERNAME_HERE'"); // ← replace later

// ▶️ Run the verifier
console.log("🧪 Testing FULL Chaum-Pedersen ZKP...");
console.log("Secret x =", x.toString());
console.log("Public y = g^x =", y.toString().substring(0, 20) + "...");
console.log("Public z = h^x =", z.toString().substring(0, 20) + "...");
console.log("Proof: { a, b, c, r } (values truncated)");

console.log("COPY THESE FOR LOGIN TEST:");
console.log("a:", a.toString());
console.log("b:", b.toString());
console.log("r:", r.toString());

const result = verifyChaumPedersen(fakeProof, y, z);

console.log("\n✅ FINAL RESULT:", result ? "VERIFICATION PASSED!" : "VERIFICATION FAILED!");