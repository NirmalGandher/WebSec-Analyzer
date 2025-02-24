document.getElementById('analyzeForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const domain = document.getElementById('domainInput').value.trim();

    if (!domain) {
        alert('Please enter a domain name.');
        return;
    }

    // Show loading message
    const resultDiv = document.getElementById('result');
    resultDiv.innerHTML = '<p>Analyzing... Please wait.</p>';

    try {
        // Send request to backend
        const response = await fetch(`http://localhost:3000/analyze?domain=${domain}`);
        const data = await response.json();

        // Display results
        resultDiv.innerHTML = `
            <h2>Analysis Results for: ${domain}</h2>
            <p><strong>SSL/TLS Certificate:</strong></p>
            <p>Valid: ${data.sslInfo.valid ? 'Yes' : 'No'}</p>
            <p>Expiry Date: ${data.sslInfo.expiryDate || 'N/A'}</p>
            <p>Encryption: ${data.sslInfo.encryption || 'N/A'}</p>
            <p><strong>HTTPS:</strong> ${data.httpsInfo.usesHTTPS ? 'Yes' : 'No'}</p>
            <p><strong>WHOIS Info:</strong></p>
            <pre>${data.whoisInfo || 'N/A'}</pre>
        `;
    } catch (error) {
        resultDiv.innerHTML = '<p>Error analyzing the domain. Please try again.</p>';
    }
});