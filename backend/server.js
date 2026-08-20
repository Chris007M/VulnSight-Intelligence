const express = require('express');
const fileUpload = require('express-fileupload');
const path = require('path');
const fs = require('fs');

const uploadRoute = require('./routes/upload');
const authRoute = require('./routes/auth');
const remediationRoute = require('./routes/remediation');

const app = express();

app.use(fileUpload({
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB max file size
    useTempFiles: false
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static frontend files
app.use(express.static(path.join(__dirname, '../frontend')));

// API Routes
app.use('/upload', uploadRoute);
app.use('/auth', authRoute);
app.use('/api/remediation', remediationRoute);

// Reports retrieval endpoint
app.get('/api/reports', (req, res) => {
    try {
        const reportsDir = path.join(__dirname, '../reports');
        if (!fs.existsSync(reportsDir)) {
            return res.json({ reports: [] });
        }
        const files = fs.readdirSync(reportsDir).filter(f => f.endsWith('.json'));
        const reports = files.map(file => {
            const content = fs.readFileSync(path.join(reportsDir, file), 'utf-8');
            return JSON.parse(content);
        });
        res.json({ reports });
    } catch (err) {
        res.status(500).json({ error: 'Failed to retrieve reports', details: err.message });
    }
});

// Fallback to index.html for root navigation
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`===================================================`);
    console.log(` VulnSight Security Platform Server Running        `);
    console.log(` Access Dashboard at: http://localhost:${PORT}     `);
    console.log(`===================================================`);
});

