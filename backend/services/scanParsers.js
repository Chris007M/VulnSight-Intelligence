/**
 * scanParsers.js — VulnSight Multi-Format Scan File Parser
 *
 * Supported formats:
 *   .xml    — Nmap XML output (-oX)
 *   .txt    — Nmap normal output (-oN)
 *   .gnmap  — Nmap grepable output (-oG)
 *   .html   — Nmap HTML report
 *   .xlsx / .xls — Excel spreadsheet (columns: IP, Port, Protocol, Service, Product, Version, State)
 *   .csv    — CSV (same column convention as xlsx)
 *   .json   — Masscan JSON or generic host/port JSON array
 */

const xml2js = require('xml2js');
const XLSX   = require('xlsx');
const { parse: csvParse } = require('csv-parse/sync');

// ─────────────────────────────────────────────────────────────────────────────
// Master dispatcher
// ─────────────────────────────────────────────────────────────────────────────
async function detectFormatAndParse(filename, buffer) {
    const ext = (filename.split('.').pop() || '').toLowerCase();

    switch (ext) {
        case 'xml':   return parseXML(buffer.toString('utf-8'));
        case 'txt':   return parseTXT(buffer.toString('utf-8'));
        case 'gnmap': return parseGNMAP(buffer.toString('utf-8'));
        case 'html':
        case 'htm':   return parseHTML(buffer.toString('utf-8'));
        case 'xlsx':
        case 'xls':   return parseXLSX(buffer);
        case 'csv':   return parseCSV(buffer.toString('utf-8'));
        case 'json':  return parseJSON(buffer.toString('utf-8'));
        default:
            // Try sniffing content
            const text = buffer.toString('utf-8');
            if (text.trimStart().startsWith('<')) return parseXML(text);
            if (text.includes('Host:') && text.includes('Ports:')) return parseGNMAP(text);
            if (text.includes('Nmap scan report')) return parseTXT(text);
            if (text.trimStart().startsWith('[') || text.trimStart().startsWith('{')) return parseJSON(text);
            throw new Error(`Unsupported file format: .${ext}. Supported: .xml, .txt, .gnmap, .html, .xlsx, .xls, .csv, .json`);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Normalizer — ensures output shape matches what riskAnalyzer expects
// ─────────────────────────────────────────────────────────────────────────────
function normalizeHost(ip, hostname, ports) {
    return {
        ip: ip || 'Unknown IP',
        hostname: hostname || '',
        ports: (ports || []).map(p => ({
            port:     String(p.port || p.portid || 'Unknown'),
            protocol: p.protocol || 'tcp',
            service:  p.service  || p.name   || 'unknown',
            product:  p.product  || '',
            version:  p.version  || '',
            state:    p.state    || 'open'
        }))
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// XML — Nmap -oX
// ─────────────────────────────────────────────────────────────────────────────
async function parseXML(xmlData) {
    const parser = new xml2js.Parser({ explicitArray: true, mergeAttrs: false });
    const result = await parser.parseStringPromise(xmlData);

    if (!result || !result.nmaprun) {
        throw new Error('Invalid Nmap XML format: Missing <nmaprun> root tag');
    }

    let rawHosts = result.nmaprun.host || [];
    if (!Array.isArray(rawHosts)) rawHosts = [rawHosts];

    return rawHosts.map(host => {
        let ip = 'Unknown IP';
        if (host.address) {
            const addrs = Array.isArray(host.address) ? host.address : [host.address];
            const ipv4  = addrs.find(a => a.$ && (a.$.addrtype === 'ipv4' || !a.$.addrtype));
            ip = ipv4 ? ipv4.$.addr : (addrs[0].$ ? addrs[0].$.addr : 'Unknown IP');
        }

        let hostname = '';
        if (host.hostnames && host.hostnames[0] && host.hostnames[0].hostname) {
            const hList = host.hostnames[0].hostname;
            if (hList[0] && hList[0].$) hostname = hList[0].$.name || '';
        }

        let ports = [];
        if (host.ports && host.ports[0] && host.ports[0].port) {
            let rawPorts = host.ports[0].port;
            if (!Array.isArray(rawPorts)) rawPorts = [rawPorts];

            ports = rawPorts.map(p => {
                const portId   = p.$ ? p.$.portid : 'Unknown';
                const protocol = p.$ ? p.$.protocol : 'tcp';
                let state      = 'unknown';
                if (p.state && p.state[0] && p.state[0].$) state = p.state[0].$.state;
                let serviceName = 'unknown', product = '', version = '';
                if (p.service && p.service[0] && p.service[0].$) {
                    const s = p.service[0].$;
                    serviceName = s.name || 'unknown';
                    product     = s.product || '';
                    version     = s.version || '';
                }
                return { port: portId, protocol, service: serviceName, product, version, state };
            });
        }

        return normalizeHost(ip, hostname, ports);
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// TXT — Nmap normal output (-oN)
// Example lines:
//   Nmap scan report for 192.168.1.1
//   22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
// ─────────────────────────────────────────────────────────────────────────────
function parseTXT(text) {
    const hosts = [];
    let currentHost = null;

    const lines = text.split('\n');
    for (const rawLine of lines) {
        const line = rawLine.trim();

        // New host block
        const hostMatch = line.match(/^Nmap scan report for (.+)/i);
        if (hostMatch) {
            if (currentHost) hosts.push(normalizeHost(currentHost.ip, currentHost.hostname, currentHost.ports));
            const target = hostMatch[1].trim();
            // Could be "hostname (ip)" or just "ip"
            const ipInParens = target.match(/\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)/);
            if (ipInParens) {
                currentHost = { ip: ipInParens[1], hostname: target.split('(')[0].trim(), ports: [] };
            } else {
                currentHost = { ip: target, hostname: '', ports: [] };
            }
            continue;
        }

        // Port line: 22/tcp open ssh OpenSSH 7.4
        if (currentHost) {
            const portMatch = line.match(/^(\d+)\/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.+))?/);
            if (portMatch) {
                currentHost.ports.push({
                    port:     portMatch[1],
                    protocol: portMatch[2],
                    state:    portMatch[3],
                    service:  portMatch[4],
                    product:  portMatch[5] ? portMatch[5].split(' ')[0] : '',
                    version:  portMatch[5] ? portMatch[5].split(' ').slice(1).join(' ') : ''
                });
            }
        }
    }
    if (currentHost) hosts.push(normalizeHost(currentHost.ip, currentHost.hostname, currentHost.ports));
    if (hosts.length === 0) throw new Error('No hosts found in TXT scan file. Ensure this is a valid Nmap -oN output.');
    return hosts;
}

// ─────────────────────────────────────────────────────────────────────────────
// GNMAP — Nmap grepable output (-oG)
// Example: Host: 192.168.1.1 ()  Ports: 22/open/tcp//ssh///
// ─────────────────────────────────────────────────────────────────────────────
function parseGNMAP(text) {
    const hosts = [];
    const lines = text.split('\n');

    for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line.startsWith('Host:')) continue;

        const ipMatch       = line.match(/Host:\s+(\S+)/);
        const hostnameMatch = line.match(/Host:\s+\S+\s+\(([^)]*)\)/);
        const portsSection  = line.match(/Ports:\s+(.+?)(?:\t|$)/);

        const ip       = ipMatch       ? ipMatch[1]       : 'Unknown IP';
        const hostname = hostnameMatch ? hostnameMatch[1] : '';
        const ports    = [];

        if (portsSection) {
            const portTokens = portsSection[1].split(',');
            for (const token of portTokens) {
                // Format: port/state/proto//service//product/version/
                const parts = token.trim().split('/');
                if (parts.length >= 3) {
                    ports.push({
                        port:     parts[0],
                        state:    parts[1] || 'open',
                        protocol: parts[2] || 'tcp',
                        service:  parts[4] || 'unknown',
                        product:  parts[6] || '',
                        version:  parts[7] || ''
                    });
                }
            }
        }
        hosts.push(normalizeHost(ip, hostname, ports));
    }
    if (hosts.length === 0) throw new Error('No hosts found in GNMAP file. Ensure this is a valid Nmap -oG output.');
    return hosts;
}

// ─────────────────────────────────────────────────────────────────────────────
// HTML — Nmap HTML report (generated by xsltproc or nmap -oX | xsl)
// Extracts table rows with port info
// ─────────────────────────────────────────────────────────────────────────────
function parseHTML(html) {
    const hosts = [];

    // Find host sections — heading with IP
    const hostBlocks = html.split(/<h2[^>]*>/i).slice(1);
    for (const block of hostBlocks) {
        const ipMatch = block.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
        if (!ipMatch) continue;
        const ip = ipMatch[1];

        const hostnameMatch = block.match(/<td[^>]*>\s*(\S+\.\S+)\s*<\/td>/i);
        const hostname = hostnameMatch ? hostnameMatch[1] : '';

        const ports = [];
        // Table row pattern: <td>port/proto</td><td>state</td><td>service</td>
        const rowMatches = [...block.matchAll(/<tr[^>]*>([\s\S]*?)<\/tr>/gi)];
        for (const rowMatch of rowMatches) {
            const cells = [...rowMatch[1].matchAll(/<td[^>]*>([\s\S]*?)<\/td>/gi)]
                .map(m => m[1].replace(/<[^>]+>/g, '').trim());

            if (cells.length >= 3) {
                const portProto = cells[0].split('/');
                if (portProto.length >= 2 && /^\d+$/.test(portProto[0])) {
                    ports.push({
                        port:     portProto[0],
                        protocol: portProto[1] || 'tcp',
                        state:    cells[1] || 'open',
                        service:  cells[2] || 'unknown',
                        product:  cells[3] || '',
                        version:  cells[4] || ''
                    });
                }
            }
        }
        if (ports.length > 0) hosts.push(normalizeHost(ip, hostname, ports));
    }
    if (hosts.length === 0) throw new Error('No hosts/ports found in HTML scan report. Ensure this is a valid Nmap HTML output.');
    return hosts;
}

// ─────────────────────────────────────────────────────────────────────────────
// XLSX / XLS — Excel spreadsheet
// Expected columns (any order, case-insensitive):
//   IP, Hostname, Port, Protocol, Service, Product, Version, State
// ─────────────────────────────────────────────────────────────────────────────
function parseXLSX(buffer) {
    const workbook = XLSX.read(buffer, { type: 'buffer' });
    const sheet    = workbook.Sheets[workbook.SheetNames[0]];
    const rows     = XLSX.utils.sheet_to_json(sheet, { defval: '' });

    if (!rows || rows.length === 0) throw new Error('Excel file is empty or has no data rows.');

    // Normalize header keys
    const normalizeKey = k => k.toString().toLowerCase().trim();
    const hostsMap = new Map();

    for (const row of rows) {
        const r = {};
        for (const [k, v] of Object.entries(row)) r[normalizeKey(k)] = v;

        const ip       = String(r['ip'] || r['host'] || r['address'] || '').trim();
        const hostname = String(r['hostname'] || r['name'] || '').trim();
        const port     = String(r['port'] || '').trim();
        const protocol = String(r['protocol'] || r['proto'] || 'tcp').trim();
        const service  = String(r['service'] || r['servicename'] || 'unknown').trim();
        const product  = String(r['product'] || '').trim();
        const version  = String(r['version'] || '').trim();
        const state    = String(r['state'] || 'open').trim();

        if (!ip || !port) continue;

        if (!hostsMap.has(ip)) hostsMap.set(ip, { ip, hostname, ports: [] });
        hostsMap.get(ip).ports.push({ port, protocol, service, product, version, state });
    }

    const hosts = [...hostsMap.values()].map(h => normalizeHost(h.ip, h.hostname, h.ports));
    if (hosts.length === 0) throw new Error('No valid host/port rows found in Excel file. Required columns: IP, Port.');
    return hosts;
}

// ─────────────────────────────────────────────────────────────────────────────
// CSV
// Expected columns: IP, Hostname, Port, Protocol, Service, Product, Version, State
// ─────────────────────────────────────────────────────────────────────────────
function parseCSV(csvText) {
    let rows;
    try {
        rows = csvParse(csvText, { columns: true, skip_empty_lines: true, trim: true });
    } catch (e) {
        throw new Error('CSV parse error: ' + e.message);
    }

    if (!rows || rows.length === 0) throw new Error('CSV file is empty or has no data rows.');

    const normalizeKey = k => k.toString().toLowerCase().trim();
    const hostsMap = new Map();

    for (const rawRow of rows) {
        const row = {};
        for (const [k, v] of Object.entries(rawRow)) row[normalizeKey(k)] = v;

        const ip       = String(row['ip'] || row['host'] || row['address'] || '').trim();
        const hostname = String(row['hostname'] || row['name'] || '').trim();
        const port     = String(row['port'] || '').trim();
        const protocol = String(row['protocol'] || row['proto'] || 'tcp').trim();
        const service  = String(row['service'] || row['servicename'] || 'unknown').trim();
        const product  = String(row['product'] || '').trim();
        const version  = String(row['version'] || '').trim();
        const state    = String(row['state'] || 'open').trim();

        if (!ip || !port) continue;

        if (!hostsMap.has(ip)) hostsMap.set(ip, { ip, hostname, ports: [] });
        hostsMap.get(ip).ports.push({ port, protocol, service, product, version, state });
    }

    const hosts = [...hostsMap.values()].map(h => normalizeHost(h.ip, h.hostname, h.ports));
    if (hosts.length === 0) throw new Error('No valid host/port rows found in CSV. Required columns: ip, port.');
    return hosts;
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON — Masscan JSON or generic host/port array
// Masscan format: [{"ip":"x.x.x.x","ports":[{"port":80,"proto":"tcp","status":"open"}]}]
// Generic format: [{ip, hostname, ports:[{port, service, ...}]}]
// ─────────────────────────────────────────────────────────────────────────────
function parseJSON(jsonText) {
    let data;
    try {
        data = JSON.parse(jsonText);
    } catch (e) {
        throw new Error('JSON parse error: ' + e.message);
    }

    const items = Array.isArray(data) ? data : (data.hosts || data.results || [data]);
    if (!items || items.length === 0) throw new Error('JSON file contains no host data.');

    const hostsMap = new Map();

    for (const item of items) {
        // Masscan: { ip: "x.x.x.x", ports: [{port, proto, status}] }
        // Generic: { ip, hostname, ports: [{port, service, ...}] }
        const ip       = String(item.ip || item.address || item.host || '').trim();
        const hostname = String(item.hostname || item.name || '').trim();

        if (!ip) continue;
        if (!hostsMap.has(ip)) hostsMap.set(ip, { ip, hostname, ports: [] });

        const rawPorts = item.ports || item.openPorts || [];
        for (const p of rawPorts) {
            hostsMap.get(ip).ports.push({
                port:     String(p.port || p.portid || ''),
                protocol: String(p.proto || p.protocol || 'tcp'),
                state:    String(p.status || p.state || 'open'),
                service:  String(p.service || p.name || 'unknown'),
                product:  String(p.product || ''),
                version:  String(p.version || '')
            });
        }
    }

    const hosts = [...hostsMap.values()].map(h => normalizeHost(h.ip, h.hostname, h.ports));
    if (hosts.length === 0) throw new Error('No valid hosts found in JSON. Expected array with ip and ports fields.');
    return hosts;
}

module.exports = { detectFormatAndParse, parseXML, parseTXT, parseGNMAP, parseHTML, parseXLSX, parseCSV, parseJSON };
