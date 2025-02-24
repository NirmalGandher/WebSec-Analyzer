const express = require('express');
const axios = require('axios');
const sslChecker = require('ssl-checker');
const whois = require('whois');
const cors = require('cors');

const app = express();
const PORT = 3000;

// Enable CORS
app.use(cors());

// Serve static files (HTML, CSS, JS)
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

        res.json({ domain, sslInfo, httpsInfo, whoisInfo });
    } catch (error) {
        console.error('Error analyzing domain:', error); // Log the error
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
                resolve('WHOIS information not available for this domain.');
            } else {
                resolve(data);
            }
        });
    });
}

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});