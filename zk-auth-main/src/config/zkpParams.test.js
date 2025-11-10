// src/config/zkpParams.test.js
import { ZKP_PARAMS } from './zkpParams.js';

console.log("Prime p is:", ZKP_PARAMS.p.toString());
console.log("Prime q is:", ZKP_PARAMS.q.toString());
console.log("Generator g is:", ZKP_PARAMS.g.toString());

// Check: g^q mod p should be 1 (this is a math rule!)
import modExp from '../utils/modExp.js';
const check = modExp(ZKP_PARAMS.g, ZKP_PARAMS.q, ZKP_PARAMS.p);
console.log("g^q mod p =", check.toString()); // Should be "1"