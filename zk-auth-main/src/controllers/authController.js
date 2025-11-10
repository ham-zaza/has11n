// src/controllers/authController.js
import User from '../models/User.js';
import { ZKP_PARAMS } from '../config/zkpParams.js';
import modExp from '../utils/modExp.js';
import { verifyChaumPedersen } from '../services/chaumPedersenVerifier.js'; // <-- new import

// ✅ Import crypto for ESM (keep if used elsewhere)
import { createHash, webcrypto } from 'crypto';

const { p, q, g, h } = ZKP_PARAMS;

// ── 1. User Registration ───────────────────────────────
export const registerUser = async (req, res) => {
    console.log("✅ Register route called!");
    console.log("Request body:", req.body);

    try {
        const { username, publicKeyY, publicKeyZ } = req.body;

        if (!username || !publicKeyY) {
            return res.status(400).json({ message: "Username and publicKeyY are required" });
        }

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }

        const newUser = new User({ username, publicKeyY, publicKeyZ });
        await newUser.save();

        console.log("✅ User saved:", newUser);
        res.status(201).json({
            message: "User registered successfully!",
            user: newUser
        });

    } catch (error) {
        console.error("❌ Error in registerUser:", error);
        res.status(500).json({
            message: "Internal server error",
            error: error.message
        });
    }
};

// ── 2. List All Users (for testing) ────────────────────
export const getAllUsers = async (req, res) => {
    try {
        const users = await User.find().select("-__v");
        res.status(200).json({
            message: "Users fetched successfully!",
            count: users.length,
            users: users
        });
    } catch (error) {
        console.error("❌ Error fetching users:", error);
        res.status(500).json({
            message: "Failed to fetch users",
            error: error.message
        });
    }
};

// ── 3. Non-Interactive ZKP Login ───────────────────────
export const verifyProof = async (req, res) => {
    console.log("🔍 RAW REQUEST BODY:", req.body);

    const { username, a, b, s, domain, timestamp } = req.body;

    console.log("🔍 DESTRUCTURED:", { username, a, b, s, domain, timestamp });

    if (!username || !a || !b || !s || !domain || !timestamp) {
        return res.status(400).json({
            error: "Missing proof components or timestamp",
            received: { username, a, b, s, domain, timestamp }
        });
    }

    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ error: "User not found" });
        }

        if (!user.publicKeyY || !user.publicKeyZ) {
            return res.status(400).json({
                error: "User missing public keys",
                user: { publicKeyY: user.publicKeyY, publicKeyZ: user.publicKeyZ }
            });
        }

        // Convert numeric strings to BigInt
        const proof = {
            a: BigInt(a),
            b: BigInt(b),
            s: BigInt(s),
            domain: domain,
            timestamp: Number(timestamp) // verifier checks timestamp as number
        };

        const Y = BigInt(user.publicKeyY);
        const Z = BigInt(user.publicKeyZ);

        // Call centralized verifier (this produces the logs you expect)
        const valid = verifyChaumPedersen(proof, Y, Z);

        if (valid) {
            console.log("✅ Login successful!");
            return res.json({ message: "✅ Login successful!" });
        }  else {
            console.log("❌ Invalid proof (verifier returned false)");
            return res.status(401).json({ error: "❌ Invalid proof" });
        }
    } catch (err) {
        console.error("💥 Verification crash:", err);
        return res.status(500).json({ error: "Verification crashed", details: err.message });
    }
};
