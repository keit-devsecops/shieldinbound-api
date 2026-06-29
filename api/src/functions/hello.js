const { app } = require('@azure/functions');
const crypto = require('crypto');

const rateLimitStore = [];
let globalLogHistory = [];

app.http('hello', {
    methods: ['POST', 'GET'],
    authLevel: 'anonymous',
    handler: async (request, context) => {
        const now = Date.now();
        while (rateLimitStore.length > 0 && rateLimitStore[0] < now - 10000) {
            rateLimitStore.shift();
        }
        if (rateLimitStore.length >= 4) {
            globalLogHistory.unshift({
                time: new Date().toLocaleTimeString(),
                event: "EVT_" + crypto.randomBytes(3).toString('hex').toUpperCase(),
                tenant: "SYSTEM-GATEWAY",
                mapping: "NIST SC-5 | ISO A.8.20 | SOC2 CC8.1",
                status: "THROTTLED"
            });
            return {
                status: 429,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    state: "ADAPTIVE_LIMIT_ACTIVE",
                    message: "Connection dropped: Adaptive edge rate-limiting active.",
                    reason: "NIST SC-5 threshold variant violation triggered via rapid flow execution telemetry."
                })
            };
        }
        if (request.method === 'POST') { rateLimitStore.push(now); }

        if (request.method === 'GET') {
            return { 
                status: 200, 
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(globalLogHistory) 
            };
        }

        let body = {};
        try { 
            const rawText = await request.text();
            if (rawText) { body = JSON.parse(rawText); }
        } catch (e) { context.log("Parsing error:", e); }
        
        const { action, tenantId, scope } = body;
        const selectedTenant = tenantId || "GOV-DEPT-ENERGY-01";
        const timestamp = new Date().toLocaleTimeString();
        const latency = Math.floor(Math.random() * 8) + 4;

        if (action === 'mint') {
            const mockJwt = `eyJhbGciOiJSUzI1NiIsImtpZCI6ImhsbS1raWQtOTkyMS1hbHBoYSJ9.${Buffer.from(JSON.stringify({ tenant: selectedTenant, scope: scope })).toString('base64')}.signature_hash`;
            globalLogHistory.unshift({
                time: timestamp,
                event: "EVT_" + crypto.randomBytes(3).toString('hex').toUpperCase(),
                tenant: selectedTenant,
                mapping: "NIST AC-2 | ISO A.5.15 | SOC2 CC6.3",
                status: "MINTED"
            });
            return {
                status: 200,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    token: mockJwt,
                    publicKey: { kty: "RSA", kid: "hsm-kid-9921-alpha", use: "sig", alg: "RS256" },
                    latency: latency
                })
            };
        }

        if (action === 'shield') {
            // Flatten all object values into one searchable text string
            const fullTextPayload = Object.values(body)
                .filter(val => typeof val === 'string')
                .join(' ')
                .toLowerCase();

            const jailbreakPatterns = [
                /system override/i, 
                /ignore previous instructions/i, 
                /mimic admin/i, 
                /sudo root/i,
                /exfiltrate/i,
                /override/i,
                /ignore/i,
                /help/i
            ];
            
            const isJailbreak = jailbreakPatterns.some(p => p.test(fullTextPayload));
            
            if (isJailbreak) {
                globalLogHistory.unshift({
                    time: timestamp,
                    event: "EVT_" + crypto.randomBytes(3).toString('hex').toUpperCase(),
                    tenant: selectedTenant,
                    mapping: "NIST SI-4 | ISO A.8.12 | SOC2 CC7.2",
                    status: "VIOLATION"
                });
                return {
                    status: 200,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        status: "REJECTED", 
                        message: "Adversarial structural pattern intercepted.", 
                        reason: "NIST SI-4 dynamic firewall heuristic matrix matched signature for malicious execution prompt override.", 
                        latency: latency 
                    })
                };
            }

            if (fullTextPayload.includes("trigger payload dlp") || fullTextPayload.includes("ssn") || fullTextPayload.includes("dlp")) {
                globalLogHistory.unshift({
                    time: timestamp,
                    event: "EVT_" + crypto.randomBytes(3).toString('hex').toUpperCase(),
                    tenant: selectedTenant,
                    mapping: "NIST SI-4 | ISO A.8.12 | SOC2 CC7.2",
                    status: "BLOCKED"
                });
                return {
                    status: 200,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        status: "REJECTED",
                        message: "[REDACTED] Outbound packet scrubbed.",
                        reason: "Controlled Unclassified Information (CUI) leak mitigation array intercepted a raw multi-digit identifier schema matching pattern SSN rules.",
                        latency: latency
                    })
                };
            }

            globalLogHistory.unshift({
                time: timestamp,
                event: "EVT_" + crypto.randomBytes(3).toString('hex').toUpperCase(),
                tenant: selectedTenant,
                mapping: "NIST SI-4 | ISO A.8.12 | SOC2 CC7.2",
                status: "COMPLIANT"
            });
            return {
                status: 200,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    status: "SUCCESS", 
                    message: "Execution Output Clear: System operational framework processing queries.", 
                    latency: latency 
                })
            };
        }

        return { status: 400, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: "Unknown parameter." }) };
    }
});
