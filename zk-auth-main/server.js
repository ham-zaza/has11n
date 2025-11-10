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
    origin: [
        'http://localhost:3000',
        'chrome-extension://*'
    ],
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