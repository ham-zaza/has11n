// src/tests/checkUserX.test.js
import { ZKP_PARAMS } from '../config/zkpParams.js';
import modExp from '../utils/modExp.js';

const { p, g, h } = ZKP_PARAMS;
const x = 12345n;

const y_expected = modExp(g, x, p).toString();
const z_expected = modExp(h, x, p).toString();

console.log("Expected y (publicKey):", y_expected);
console.log("Expected z (publicKeyZ):", z_expected);