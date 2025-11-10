// src/utils/modExp.test.js
import modExp from './modExp.js'; // 👈 NOTE: .js at the end is REQUIRED!

// Test: 2^3 mod 5 = 8 mod 5 = 3
console.log("Test 1:", modExp(2n, 3n, 5n).toString()); // Should print "3"

// Test: 10^2 mod 6 = 100 mod 6 = 4
console.log("Test 2:", modExp(10n, 2n, 6n).toString()); // Should print "4"