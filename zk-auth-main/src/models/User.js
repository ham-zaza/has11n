// src/models/User.js
import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    // y = g^x mod p
    publicKeyY: {
        type: String,
        required: true
    },
    // z = h^x mod p
    publicKeyZ: {
        type: String,
        required: true  // now required
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

export default mongoose.model('User', userSchema);