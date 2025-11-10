// src/tests/stage1.test.js
import fetch from 'node-fetch';

const testUser = {
    username: 'stage1_user_' + Date.now(),
    publicKey: 'abc123xyz_stage1'
};

async function testRegister() {
    const res = await fetch('http://localhost:3000/api/users/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(testUser)
    });
    const data = await res.json();
    console.log("📌 Stage 1 Register:", data.message || data.error);
}

// Start server, run test, then exit
(async () => {
    // Launch server in background (simulate)
    console.log("🚀 Starting server for Stage 1 test...");
    const server = await import('../server.js').catch(() => {});
    setTimeout(testRegister, 2000); // Wait 2s for server to start
})();