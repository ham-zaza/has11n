import fetch from 'node-fetch';
globalThis.fetch = fetch;
// src/tests/loginZKP.test.js
import fetch from 'node-fetch'; // We'll install this next!

const username = 'zkp_user_1760822929227'; // ← USE YOUR USERNAME FROM EARLIER!

// 🔑 Fake proof (same as your working test)
const proof = {
    a: " 11196187812524768586064218974492394649500049443937269167968648938676871527393", // ← REPLACE!
    b: "35731605468657991598792381857660295464689365160307633838141976057223313244424", // ← REPLACE!
    c: "999",
    r: "12400545" // ← REPLACE!
};

// We'll send this to /api/auth/login