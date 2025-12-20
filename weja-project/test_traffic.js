/**
 * WEJÀ Traffic Test Script
 * Sends safe and malicious requests to test WAF detection.
 */

const axios = require('axios');

const WAF_URL = 'http://localhost:3000/proxy';

const testCases = [
    // Safe requests
    {
        name: 'Safe GET request',
        method: 'GET',
        url: `${WAF_URL}/`,
        expected: 200
    },
    {
        name: 'Safe search',
        method: 'GET',
        url: `${WAF_URL}/search?q=hello`,
        expected: 200
    },
    {
        name: 'Safe login',
        method: 'POST',
        url: `${WAF_URL}/login`,
        data: { username: 'john', password: 'secret123' },
        expected: 200
    },

    // SQL Injection attacks
    {
        name: 'SQLi - Basic OR injection',
        method: 'GET',
        url: `${WAF_URL}/search?q=' OR 1=1 --`,
        expected: 403
    },
    {
        name: 'SQLi - UNION attack',
        method: 'GET',
        url: `${WAF_URL}/users/'UNION SELECT * FROM users--`,
        expected: 403
    },
    {
        name: 'SQLi - Login bypass',
        method: 'POST',
        url: `${WAF_URL}/login`,
        data: { username: "admin'--", password: 'anything' },
        expected: 403
    },

    // XSS attacks
    {
        name: 'XSS - Script tag',
        method: 'POST',
        url: `${WAF_URL}/comment`,
        data: { content: '<script>alert("XSS")</script>' },
        expected: 403
    },
    {
        name: 'XSS - Event handler',
        method: 'GET',
        url: `${WAF_URL}/search?q=<img src=x onerror=alert(1)>`,
        expected: 403
    },
    {
        name: 'XSS - JavaScript protocol',
        method: 'POST',
        url: `${WAF_URL}/comment`,
        data: { content: 'javascript:alert(document.cookie)' },
        expected: 403
    },

    // Path Traversal attacks
    {
        name: 'Path Traversal - Basic',
        method: 'GET',
        url: `${WAF_URL}/file?name=../../../etc/passwd`,
        expected: 403
    },
    {
        name: 'Path Traversal - Windows',
        method: 'GET',
        url: `${WAF_URL}/file?name=..\\..\\windows\\system32\\config`,
        expected: 403
    },

    // Command Injection
    {
        name: 'Command Injection - Semicolon',
        method: 'GET',
        url: `${WAF_URL}/search?q=test; cat /etc/passwd`,
        expected: 403
    },
    {
        name: 'Command Injection - Backticks',
        method: 'POST',
        url: `${WAF_URL}/comment`,
        data: { content: '`whoami`' },
        expected: 403
    }
];

async function runTests() {
    console.log('\n🧪 WEJÀ WAF Test Suite');
    console.log('='.repeat(50));

    let passed = 0;
    let failed = 0;

    for (const test of testCases) {
        try {
            const config = {
                method: test.method,
                url: test.url,
                data: test.data,
                validateStatus: () => true, // Don't throw on any status
                timeout: 5000
            };

            const response = await axios(config);
            const success = response.status === test.expected;

            if (success) {
                console.log(`✅ PASS: ${test.name} (${response.status})`);
                passed++;
            } else {
                console.log(`❌ FAIL: ${test.name} - Expected ${test.expected}, got ${response.status}`);
                failed++;
            }
        } catch (error) {
            console.log(`💥 ERROR: ${test.name} - ${error.message}`);
            failed++;
        }
    }

    console.log('='.repeat(50));
    console.log(`\n📊 Results: ${passed} passed, ${failed} failed`);
    console.log(`🎯 Success rate: ${((passed / testCases.length) * 100).toFixed(1)}%\n`);

    return failed === 0;
}

// Run if executed directly
runTests()
    .then(success => {
        process.exit(success ? 0 : 1);
    })
    .catch(err => {
        console.error('Test suite failed:', err);
        process.exit(1);
    });
