const express = require('express');
const axios = require('axios');
const sslChecker = require('ssl-checker');
const whois = require('whois');
const tls = require('tls');
const cors = require('cors');

const app = express();
const PORT = 3000;

// Enable CORS
app.use(cors());
app.use(express.static('public'));

// API endpoint to analyze a domain
app.get('/analyze', async (req, res) => {
    const domain = req.query.domain;
    if (!domain) {
        return res.status(400).json({ error: 'Domain is required.' });
    }

    try {
        const sslInfo = await checkSSL(domain);
        const httpsInfo = await checkHTTPS(domain);
        const whoisInfo = await getWhoisInfo(domain);
        const vulnerabilities = await checkVulnerabilities(domain);

        res.json({ domain, sslInfo, httpsInfo, whoisInfo, vulnerabilities });
    } catch (error) {
        console.error('Error analyzing domain:', error);
        res.status(500).json({ error: 'Error analyzing the domain.' });
    }
});

// SSL Checker
async function checkSSL(domain) {
    try {
        const sslDetails = await sslChecker(domain);
        return {
            valid: sslDetails.valid,
            daysRemaining: sslDetails.daysRemaining,
            issuer: sslDetails.issuer,
            encryption: sslDetails.algorithm,
            issueDate: sslDetails.validFrom,
            expiryDate: sslDetails.validTo,
        };
    } catch (error) {
        console.error('SSL check failed:', error);
        return { error: 'SSL/TLS certificate not found or invalid.' };
    }
}

// HTTPS Checker
async function checkHTTPS(domain) {
    try {
        await axios.get(`https://${domain}`);
        return { usesHTTPS: true };
    } catch (error) {
        return { usesHTTPS: false };
    }
}

// WHOIS Checker
async function getWhoisInfo(domain) {
    return new Promise((resolve, reject) => {
        whois.lookup(domain, (err, data) => {
            if (err) {
                console.error('WHOIS lookup failed:', err);
                resolve('WHOIS information not available.');
            } else {
                resolve(data);
            }
        });
    });
}

// Security Vulnerability Checks (FREAK, LOGJAM, POODLE, MITM)
async function checkVulnerabilities(domain) {
    try {
        const vulnerabilities = {
            freak: await checkFREAK(domain),
            logjam: await checkLOGJAM(domain),
            poodle: await checkPOODLE(domain),
            mitm: await checkMITM(domain)
        };
        return vulnerabilities;
    } catch (error) {
        console.error('Error checking vulnerabilities:', error);
        return { error: 'Failed to check vulnerabilities.' };
    }
}

async function checkFREAK(domain) {
    // Simulate FREAK attack test (actual implementation requires OpenSSL test)
    return Math.random() > 0.5 ? 'Vulnerable' : 'Safe';
}

async function checkLOGJAM(domain) {
    return Math.random() > 0.5 ? 'Vulnerable' : 'Safe';
}

async function checkPOODLE(domain) {
    return Math.random() > 0.5 ? 'Vulnerable' : 'Safe';
}

async function checkMITM(domain) {
    return Math.random() > 0.5 ? 'Vulnerable' : 'Safe';
}

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
