// server.js
import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import { connectDB } from './src/config/db.js';
import authRoutes from './src/routes/authRoutes.js';

dotenv.config();

const app = express();

// Middleware
app.use(express.json());
app.use(cors({
    origin: (origin, callback) => {
        // Allow no-origin (like curl, Postman) and localhost web app
        if (!origin) return callback(null, true);
        if (origin.startsWith('http://localhost') || origin.startsWith('http://127.0.0.1')) {
            return callback(null, true);
        }
        if (origin.startsWith('chrome-extension://')) {
            return callback(null, true);
        }
        // deny others
        return callback(new Error('Not allowed by CORS'), false);
    },
    credentials: true
}));


// DB
connectDB();

// Routes — all under /api
app.use('/api', authRoutes);

// Debug
app.get('/debug', (req, res) => {
    res.json({ message: '✅ Backend ready for non-interactive ZKP!' });
});

app.get('/', (req, res) => {
    res.send('ZK-Auth Backend — Non-Interactive ZKP Ready');
});

// Start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});