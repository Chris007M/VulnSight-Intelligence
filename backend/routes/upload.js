const express = require('express');
const router  = express.Router();
const { detectFormatAndParse } = require('../services/scanParsers');
const riskAnalyzer    = require('../services/riskAnalyzer');
const reportGenerator = require('../services/reportGenerator');

router.post('/', async (req, res) => {
    try {
        if (!req.files || !req.files.scanFile) {
            return res.status(400).json({
                error: 'No scan file uploaded.',
                hint:  'Supported formats: .xml, .txt, .gnmap, .html, .xlsx, .xls, .csv, .json'
            });
        }

        const scanFile = req.files.scanFile;
        const filename = scanFile.name || 'unknown';
        const buffer   = scanFile.data;

        if (!buffer || buffer.length === 0) {
            return res.status(400).json({ error: 'Uploaded file is empty.' });
        }

        // Detect format and parse into normalized host/port structure
        const parsedData = await detectFormatAndParse(filename, buffer);

        if (!parsedData || parsedData.length === 0) {
            return res.status(422).json({ error: 'No hosts or ports found in the uploaded scan file.' });
        }

        const riskResults = await riskAnalyzer(parsedData);
        const report      = reportGenerator(riskResults);

        return res.json({
            success:       true,
            filename:      filename,
            formatDetected: filename.split('.').pop().toUpperCase(),
            hostsFound:    parsedData.length,
            report:        report
        });

    } catch (err) {
        console.error('Error processing scan upload:', err);
        return res.status(500).json({
            error:   'Failed to process scan file.',
            details: err.message
        });
    }
});

module.exports = router;
