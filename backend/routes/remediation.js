const express = require('express');
const router = express.Router();
const { generateRemediationScript } = require('../services/remediationGenerator');

router.post('/generate', (req, res) => {
    try {
        const { hostIp, risks, format } = req.body;
        if (!hostIp) {
            return res.status(400).json({ error: 'hostIp parameter is required' });
        }

        const scriptContent = generateRemediationScript(hostIp, risks || [], format || 'bash');
        
        const ext = format === 'ansible' ? 'yml' : format === 'powershell' ? 'ps1' : 'sh';
        const filename = `vulnsight-hardening-${hostIp.replace(/[^a-zA-Z0-9]/g, '_')}.${ext}`;

        return res.json({
            success: true,
            filename,
            format: format || 'bash',
            script: scriptContent
        });
    } catch (err) {
        console.error('Error generating remediation script:', err);
        return res.status(500).json({ error: 'Failed to generate remediation script', details: err.message });
    }
});

module.exports = router;
