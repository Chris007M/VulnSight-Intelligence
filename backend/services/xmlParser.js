const xml2js = require('xml2js');

async function parseXML(xmlData) {
    const parser = new xml2js.Parser({ explicitArray: true, mergeAttrs: false });
    const result = await parser.parseStringPromise(xmlData);

    if (!result || !result.nmaprun) {
        throw new Error('Invalid Nmap XML format: Missing <nmaprun> root tag');
    }

    let rawHosts = result.nmaprun.host || [];
    if (!Array.isArray(rawHosts)) {
        rawHosts = [rawHosts];
    }

    return rawHosts.map(host => {
        // Extract IP address
        let ip = 'Unknown IP';
        if (host.address) {
            const addrs = Array.isArray(host.address) ? host.address : [host.address];
            const ipv4 = addrs.find(a => a.$ && (a.$.addrtype === 'ipv4' || !a.$.addrtype));
            ip = ipv4 ? ipv4.$.addr : (addrs[0].$ ? addrs[0].$.addr : 'Unknown IP');
        }

        // Extract hostname if available
        let hostname = '';
        if (host.hostnames && host.hostnames[0] && host.hostnames[0].hostname) {
            const hList = host.hostnames[0].hostname;
            if (hList[0] && hList[0].$) {
                hostname = hList[0].$.name || '';
            }
        }

        // Extract ports
        let ports = [];
        if (host.ports && host.ports[0] && host.ports[0].port) {
            let rawPorts = host.ports[0].port;
            if (!Array.isArray(rawPorts)) {
                rawPorts = [rawPorts];
            }

            ports = rawPorts.map(p => {
                const portId = p.$ ? p.$.portid : 'Unknown';
                const protocol = p.$ ? p.$.protocol : 'tcp';
                
                let state = 'unknown';
                if (p.state && p.state[0] && p.state[0].$) {
                    state = p.state[0].$.state;
                }

                let serviceName = 'unknown';
                let product = '';
                let version = '';

                if (p.service && p.service[0] && p.service[0].$) {
                    const sAttr = p.service[0].$;
                    serviceName = sAttr.name || 'unknown';
                    product = sAttr.product || '';
                    version = sAttr.version || '';
                }

                return {
                    port: portId,
                    protocol: protocol,
                    service: serviceName,
                    product: product,
                    version: version,
                    state: state
                };
            });
        }

        return {
            ip,
            hostname,
            ports
        };
    });
}

module.exports = parseXML;

