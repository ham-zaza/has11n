// src/routes/authRoutes.js
import { Router } from 'express';
import {
    registerUser,
    getAllUsers,
    verifyProof
} from '../controllers/authController.js';

const router = Router();

router.post('/register', registerUser);
router.get('/users', getAllUsers);
router.post('/login', verifyProof); // ← no /challenge needed

export default router;