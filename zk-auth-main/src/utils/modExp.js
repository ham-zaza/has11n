// src/utils/modExp.js
// This does: (base ^ exponent) % modulus
// Example: modExp(2, 3, 5) = (2*2*2) % 5 = 8 % 5 = 3

function modExp(base, exponent, modulus) {
    if (modulus === 1n) return 0n;
    let result = 1n;
    base = base % modulus;
    while (exponent > 0n) {
        if (exponent % 2n === 1n) {
            result = (result * base) % modulus;
        }
        exponent = exponent >> 1n;
        base = (base * base) % modulus;
    }
    return result;
}

export default modExp;