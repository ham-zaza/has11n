// compute-keys.js
import modExp from './src/utils/modExp.js';

const ZKP_PARAMS = {
    p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
    q: 0x7fffffff800000008000000000000000000000007fffffffffffffffffffffffn,
    g: 0x2n,
    h: 0x3n
};

const x = 12345n;

const y = modExp(ZKP_PARAMS.g, x, ZKP_PARAMS.p);
const z = modExp(ZKP_PARAMS.h, x, ZKP_PARAMS.p);

console.log('✅ REAL publicKey (y = g^x mod p):', y.toString());
console.log('✅ REAL publicKeyZ (z = h^x mod p):', z.toString());