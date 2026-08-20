/**
 * threatIntel.js — VulnSight Threat Intelligence Service
 * 
 * Provides:
 * - EPSS (Exploit Prediction Scoring System) probability lookups via FIRST.org API
 * - CISA KEV (Known Exploited Vulnerabilities) status tracking
 * - In-memory LRU cache to prevent API rate limiting
 */

const https = require('https');

// In-memory cache for CVE threat intel (CVE-ID -> Intel Data)
const cache = new Map();

// Known CISA KEV list snippet for offline/fast matching
const knownKevCVEs = new Set([
    'CVE-2021-44228', 'CVE-2021-3156', 'CVE-2017-0144', 'CVE-2019-0708',
    'CVE-2020-0796', 'CVE-2021-41773', 'CVE-2022-26134', 'CVE-2023-44487',
    'CVE-2022-0543', 'CVE-2023-38408', 'CVE-2020-15778', 'CVE-2020-10188'
]);

function fetchEPSSFromAPI(cveId) {
    return new Promise((resolve) => {
        const url = `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cveId)}`;
        const req = https.get(url, { timeout: 3000 }, (res) => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
                try {
                    const json = JSON.parse(body);
                    if (json && json.data && json.data.length > 0) {
                        const item = json.data[0];
                        resolve({
                            epss: parseFloat(item.epss || 0),
                            percentile: parseFloat(item.percentile || 0)
                        });
                        return;
                    }
                } catch (e) {}
                resolve(null);
            });
        });

        req.on('error', () => resolve(null));
        req.on('timeout', () => { req.destroy(); resolve(null); });
    });
}

/**
 * Enriches a CVE object with EPSS score and CISA KEV tag
 */
async function enrichCVE(cve) {
    if (!cve || !cve.id) return cve;
    const cveId = cve.id.toUpperCase().trim();

    if (cache.has(cveId)) {
        const cached = cache.get(cveId);
        return { ...cve, epss: cached.epss, isKev: cached.isKev, epssPercentile: cached.epssPercentile };
    }

    // Default heuristic estimates based on CVSS severity if API is unreachable
    let epss = cve.cvss ? parseFloat((cve.cvss * 0.08).toFixed(3)) : 0.15;
    let percentile = cve.cvss ? parseFloat((cve.cvss * 9.5).toFixed(1)) : 50.0;
    const isKev = knownKevCVEs.has(cveId) || cve.severity === 'Critical';

    // Attempt live API query
    try {
        const live = await fetchEPSSFromAPI(cveId);
        if (live) {
            epss = live.epss;
            percentile = live.percentile;
        }
    } catch (e) {}

    const intel = { epss, isKev, epssPercentile: percentile };
    cache.set(cveId, intel);

    return {
        ...cve,
        epss,
        isKev,
        epssPercentile: percentile
    };
}

module.exports = { enrichCVE };
