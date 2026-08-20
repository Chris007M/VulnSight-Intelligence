const express = require('express');
const router = express.Router();
const nodemailer = require('nodemailer');
const crypto = require('crypto');

let codes = {};

router.post('/send-code', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email || !email.includes('@')) {
            return res.status(400).json({ error: 'Valid email address is required' });
        }

        const code = crypto.randomInt(100000, 999999).toString();
        codes[email] = code;

        // Check if SMTP environment variables are configured
        if (process.env.SMTP_USER && process.env.SMTP_PASS) {
            try {
                const transporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
                });

                await transporter.sendMail({
                    from: process.env.SMTP_USER,
                    to: email,
                    subject: 'Your VulnSight Authentication Code',
                    text: `Your VulnSight authentication code is: ${code}`
                });

                return res.json({ success: true, message: 'Verification code sent via email.' });
            } catch (mailError) {
                console.warn('SMTP sending failed, using local dev fallback:', mailError.message);
            }
        }

        // Local development / fallback mode when SMTP is unavailable
        console.log(`[VulnSight Auth Dev Fallback] Code for ${email}: ${code}`);
        return res.json({
            success: true,
            devMode: true,
            devCode: code,
            message: `Verification code generated! (Dev mode code: ${code})`
        });
    } catch (err) {
        console.error('Auth send-code error:', err);
        return res.status(500).json({ error: 'Failed to process authentication request' });
    }
});

router.post('/verify-code', (req, res) => {
    const { email, code } = req.body;
    if (!email || !code) {
        return res.status(400).json({ error: 'Email and verification code are required' });
    }

    if (codes[email] && codes[email] === String(code).trim()) {
        delete codes[email];
        return res.json({ success: true, message: 'Authentication successful' });
    } else {
        return res.status(401).json({ error: 'Invalid or expired verification code' });
    }
});

module.exports = router;

