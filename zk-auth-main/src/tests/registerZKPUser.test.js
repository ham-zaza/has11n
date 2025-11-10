// src/tests/registerZKPUser.test.js
import mongoose from 'mongoose';
import User from '../models/User.js';
import { ZKP_PARAMS } from '../config/zkpParams.js';
import modExp from '../utils/modExp.js';

// Wrap in async IIFE because top-level await needs it in some setups
(async () => {
    try {
        // Connect to DB
        await mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/zk-auth');
        console.log("✅ Connected to MongoDB");

        // 🔑 Fake user secret
        const x = 12345n;

        // 🔑 Generate TWO public keys
        const y = modExp(ZKP_PARAMS.g, x, ZKP_PARAMS.p).toString();
        const z = modExp(ZKP_PARAMS.h, x, ZKP_PARAMS.p).toString();

        // 📦 User data
        const userData = {
            username: 'zkp_user_' + Date.now(),
            publicKeyY: y,
            publicKeyZ: z
        };

        // 💾 Save to DB
        const newUser = new User(userData);
        await newUser.save();

        console.log("✅ New ZKP user registered!");
        console.log("Username:", newUser.username);
        console.log("publicKeyY (y):", newUser.publicKeyY.substring(0, 20) + "...");
        console.log("publicKeyZ (z):", newUser.publicKeyZ.substring(0, 20) + "...");

    } catch (err) {
        console.error("❌ Error:", err.message);
    } finally {
        // Close DB connection
        await mongoose.connection.close();
        console.log("🔌 MongoDB connection closed");
    }
})();