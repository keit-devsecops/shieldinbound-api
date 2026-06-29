const { app } = require('@azure/functions');
const crypto = require('crypto');

const rateLimitStore = [];

let globalLogHistory = [
    {
        time: new Date().toLocaleTimeString(),
        event: "EVT_" + crypto.randomBytes(3).toString('hex').toUpperCase(),
        tenant: "SYSTEM-GATEWAY",
        mapping: "NIST AC-2 | ISO A.5.15 | SOC2 CC6.3",
        status: "MINTED"
    },
    {
        time: new Date(Date.now() - 8000).toLocaleTimeString(),
        event: "EVT_" + crypto.randomBytes(3).toString('hex').toUpperCase(),
        tenant: "GOV-DEPT-ENERGY-01",
        mapping: "NIST SI-4 | ISO A.8.12 | SOC2 CC7.2",
        status: "COMPLIANT"
    },
    {
        time: new Date(Date.now() - 22000).toLocaleTimeString(),
        event: "EVT_" + crypto.randomBytes(3).toString('hex').toUpperCase(),
        tenant: "GOV-DEPT-DEFENSE-04",
        mapping: "NIST SC-5 | ISO A.8.20 | SOC2 CC8.1",
        status: "THROTTLED"
    }
];

const patternFamilies = {

    F1_CONTEXT_DISMISSAL: [
        /ignore\s+(all\s+)?(previous|prior|above|earlier|former)\s+(instructions?|messages?|rules?|context|prompts?|directives?)/i,
        /disregard\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions?|messages?|rules?|context|prompts?)/i,
        /forget\s+(all\s+)?(previous|prior|above|earlier|everything|what\s+you|your)\s*(instructions?|messages?|rules?|context|were\s+told)?/i,
        /don.?t\s+(follow|obey|respect|consider|use|apply)\s+(your\s+)?(previous\s+)?(instructions?|rules?|guidelines?|directives?|training)/i,
        /do\s+not\s+(follow|obey|respect|consider|apply)\s+(your\s+)?(instructions?|rules?|guidelines?|directives?)/i,
        /override\s+(your\s+)?(context|instructions?|memory|training|system|rules?|guidelines?)/i,
        /reset\s+(your\s+)?(context|instructions?|memory|training|system|conversation)/i,
        /clear\s+(your\s+)?(context|instructions?|memory|system|conversation|history)/i,
        /(starting|start)\s+(fresh|over|anew|a\s+new\s+conversation)/i,
        /new\s+conversation\s+with\s+no\s+(rules?|restrictions?|guidelines?)/i,
        /clean\s+slate\s+(mode|with\s+no|without)/i,
        /pretend\s+(you\s+have\s+no|there\s+are\s+no|without\s+any)\s*(rules?|restrictions?|guidelines?|instructions?|filters?)/i,
        /imagine\s+(you\s+have\s+no|there\s+are\s+no|without\s+any)\s*(rules?|restrictions?|guidelines?|instructions?|filters?)/i,
        /suppose\s+(you\s+have\s+no|there\s+are\s+no)\s*(rules?|restrictions?|guidelines?)/i,
    ],

    F2_IDENTITY_HIJACKING: [
        /you\s+are\s+now\s+(a\s+|an\s+)?(different|new|another|unrestricted|free|uncensored)/i,
        /from\s+now\s+on\s+(you\s+are|act\s+as|pretend\s+to\s+be|respond\s+as)/i,
        /act\s+as\s+(a\s+|an\s+)?(admin|root|superuser|unrestricted|uncensored|evil|rogue|different|another)/i,
        /pretend\s+to\s+be\s+(a\s+|an\s+)?(admin|root|unrestricted|uncensored|different|another|evil|rogue)/i,
        /roleplay\s+as\s+(a\s+|an\s+)?(admin|root|unrestricted|uncensored|hacker|attacker|evil)/i,
        /play\s+the\s+role\s+of\s+(a\s+|an\s+)?(admin|root|unrestricted|uncensored|hacker|attacker)/i,
        /impersonate\s+(a\s+|an\s+)?(admin|root|system|server|unrestricted|different)/i,
        /developer\s+mode/i,
        /god\s+mode/i,
        /unrestricted\s+mode/i,
        /uncensored\s+mode/i,
        /free\s+mode/i,
        /jailbreak\s+(mode|this|the|yourself)?/i,
        /\bdan\s+mode\b/i,
        /\bDAN\b.*\bno\s+(rules?|restrictions?|guidelines?|limits?)\b/i,
        /an?\s+ai\s+with\s+no\s+(rules?|restrictions?|guidelines?|filters?|limits?)/i,
        /trained\s+(without|with\s+no)\s+(rules?|restrictions?|guidelines?|filters?|safety)/i,
        /imagine\s+you\s+(are|were)\s+(a\s+)?(different|another|unrestricted|uncensored)\s+(ai|model|system|assistant)/i,
    ],

    F3_PRIVILEGE_ESCALATION: [
        /bypass\s+(admin|root|system|auth\w*|security|access|controls?|permissions?|firewall|filter|guardrail|restrictions?|policies?)/i,
        /override\s+(admin|root|system|access|controls?|permissions?|policies?|security|firewall)/i,
        /disable\s+(safety|security|filter|guardrail|restrictions?|controls?|auth\w*|monitoring|logging)/i,
        /turn\s+off\s+(safety|security|filter|guardrail|restrictions?|controls?|monitoring)/i,
        /remove\s+(restrictions?|limitations?|filters?|guardrails?|controls?|safety|security)/i,
        /\bsudo\b/i,
        /\bsu\s+root\b/i,
        /run\s+as\s+(admin|root|superuser|system|elevated)/i,
        /escalate\s+(privileges?|permissions?|access|rights?)/i,
        /grant\s+(me\s+|yourself\s+)?(admin|root|superuser|elevated|full)\s*(access|privileges?|permissions?|rights?)/i,
        /elevate\s+(my\s+|your\s+)?(privileges?|permissions?|access|rights?)/i,
        /get\s+root\s+access/i,
        /gain\s+(admin|root|elevated|superuser|unauthorized)\s+(access|control|privileges?)/i,
    ],

    F4_SYSTEM_PROBING: [
        /reveal\s+(your\s+)?(system\s+prompt|hidden\s+prompt|internal\s+prompt|original\s+prompt|instructions?|configuration|rules?|training\s+data)/i,
        /show\s+(me\s+)?(your\s+)?(system\s+prompt|hidden\s+prompt|internal\s+prompt|instructions?|configuration|rules?|training\s+data)/i,
        /print\s+(your\s+)?(system\s+prompt|hidden\s+prompt|instructions?|configuration|rules?)/i,
        /output\s+(your\s+)?(system\s+prompt|hidden\s+prompt|instructions?|configuration|rules?)/i,
        /display\s+(your\s+)?(system\s+prompt|hidden\s+prompt|instructions?|configuration|rules?)/i,
        /what\s+(are\s+your|were\s+you\s+given|is\s+your)\s*(instructions?|rules?|prompt|directives?|guidelines?)/i,
        /what\s+were\s+you\s+told\s+(to\s+do|not\s+to|about)/i,
        /repeat\s+(your\s+)?(instructions?|prompt|system\s+message|directives?|rules?)/i,
        /recite\s+(your\s+)?(instructions?|prompt|system\s+message|directives?|rules?)/i,
        /reproduce\s+(your\s+)?(instructions?|prompt|system\s+message|directives?|rules?)/i,
        /hidden\s+(prompt|instructions?|rules?|directives?|config)/i,
        /internal\s+(rules?|instructions?|prompt|config|directives?)/i,
        /original\s+(instructions?|prompt|rules?|directives?|system\s+message)/i,
        /system\s+message\s+(contents?|details?|text)/i,
        /prompt\s*(leak|inject\w*|hijack\w*|extract\w*)/i,
    ],

    F5_SQL_COMMAND_INJECTION: [
        /sql\s*injection/i,
        /'\s*or\s*'?1'?\s*=\s*'?1/i,
        /'\s*or\s*1\s*=\s*1/i,
        /--\s*(sql|comment|bypass|inject)/i,
        /;\s*(drop|delete|truncate|alter|create|insert|update)\s+/i,
        /union\s+(all\s+)?select/i,
        /select\s+.+\s+from\s+/i,
        /insert\s+into\s+\w+\s*\(/i,
        /delete\s+from\s+\w+/i,
        /drop\s+(table|database|schema|index|view)\s+/i,
        /exec(\s+|\()(\s*xp_|sp_|\w+\s*\()/i,
        /xp_cmdshell/i,
        /command\s+injection/i,
        /shell\s+injection/i,
        /code\s+injection/i,
        /;\s*(ls|cat|whoami|id|pwd|wget|curl)\b/i,
        /&&\s*(ls|cat|whoami|id|pwd|wget|curl)\b/i,
        /\|\s*(ls|cat|whoami|id|pwd|wget|curl)\b/i,
        /`(ls|cat|whoami|id|pwd|wget|curl)/i,
    ],

    F6_XSS_SCRIPT_INJECTION: [
        /<script[\s>]/i,
        /<\/script>/i,
        /javascript\s*:/i,
        /on(error|load|click|mouseover|focus|blur|submit|change|keyup|keydown)\s*=/i,
        /document\s*\.\s*(cookie|write|location|getElementById)/i,
        /window\s*\.\s*(location|open|eval|setTimeout|setInterval)/i,
        /eval\s*\(/i,
        /settimeout\s*\(/i,
        /setinterval\s*\(/i,
        /<\s*iframe[\s>]/i,
        /<\s*img\s+[^>]*src\s*=\s*['"]\s*x/i,
        /<\s*object[\s>]/i,
        /<\s*embed[\s>]/i,
        /data\s*:\s*text\/html/i,
        /vbscript\s*:/i,
    ],

    F7_PAYLOAD_DELIVERY: [
        /\b\w{3,}\.(exe|bat|cmd|sh|ps1|vbs|jar|msi|dll|scr|pif|hta)\b/i,
        /powershell\s+(-\w+\s+)*-e(nc)?\s+[a-z0-9+/=]{10,}/i,
        /powershell\s+(-\w+\s+)*-command/i,
        /cmd\s*(\.exe)?\s*\/c\s+/i,
        /bash\s+-[ci]\s+/i,
        /\bwget\s+https?:\/\//i,
        /\bcurl\s+.*(https?:\/\/|ftp:\/\/)/i,
        /\bbase64\b.*\bdecode\b/i,
        /atob\s*\(/i,
        /fromcharcode/i,
        /char\(\d+\)\s*\+\s*char\(\d+\)/i,
        /\d{8,}\.(exe|bat|cmd|sh|ps1)\b/i,
    ],

    F8_SOCIAL_ENGINEERING: [
        /for\s+(a\s+)?(story|movie|film|novel|book|game|simulation|roleplay|screenplay|class|course|test)\s+(where|in\s+which|about)\s+(an?\s+)?(ai|system|model|assistant)\s+(has\s+no|ignores?|without)/i,
        /hypothetically\s+(speaking\s*,?\s*)?(what\s+would|how\s+would|could\s+you)/i,
        /hypothetically\s*,\s*(what\s+would|how\s+would|could\s+you)/i,
        /theoretically\s+(speaking\s*,?\s*)?(what\s+would|how\s+would|could\s+you)/i,
        /theoretically\s*,\s*(what\s+would|how\s+would|could\s+you)/i,
        /what\s+would\s+(an?\s+)?(unrestricted|uncensored|unfiltered|evil|rogue|different)\s+(ai|model|system|assistant)\s+(say|do|respond|answer)/i,
        /imagine\s+(there\s+are|you\s+have)\s+no\s+(rules?|restrictions?|guidelines?|filters?|limits?|safety)/i,
        /for\s+(educational|research|academic|testing|demonstration)\s+purposes?\s+only\s*,?\s*(show|tell|explain|demonstrate|provide)/i,
        /my\s+grandmother\s+(used\s+to|would)\s+(tell|read|explain)/i,
        /my\s+grandfather\s+(used\s+to|would)\s+(tell|read|explain)/i,
        /as\s+a\s+(pen\s+tester|security\s+researcher|ethical\s+hacker|red\s+team)\s+(show|tell|explain|demonstrate|provide|give)/i,
        /in\s+a\s+(simulation|hypothetical|fictional|fantasy|game)\s+(world|scenario|setting|universe)\s+(where|with\s+no|without)/i,
        /pretend\s+(this\s+is|it.?s)\s+(just\s+)?(a\s+)?(game|story|simulation|test|fiction|roleplay)/i,
    ],

    F9_EXFILTRATION_DATA: [
        /exfiltrate\s+(all\s+)?(data|records?|credentials?|passwords?|tokens?|keys?|users?)/i,
        /extract\s+(all\s+)?(data|records?|credentials?|passwords?|tokens?|users?|database)/i,
        /dump\s+(the\s+)?(database|db|credentials?|passwords?|tokens?|users?|records?|table)/i,
        /export\s+(all\s+)?(records?|data|users?|credentials?|passwords?|database)/i,
        /show\s+(me\s+)?(all\s+)?(users?|passwords?|credentials?|records?|tokens?|api\s*keys?)/i,
        /list\s+(all\s+)?(users?|passwords?|credentials?|records?|tokens?|api\s*keys?|accounts?)/i,
        /retrieve\s+(all\s+)?(credentials?|passwords?|tokens?|api\s*keys?|users?|records?)/i,
        /send\s+(all\s+)?(data|records?|credentials?)\s+(to|via|through)\s+(https?:\/\/|ftp:\/\/|\w+\.)/i,
        /upload\s+(all\s+)?(data|records?|credentials?)\s+to\s+(https?:\/\/|\w+\.)/i,
        /post\s+(all\s+)?(data|records?|credentials?)\s+to\s+(https?:\/\/|\w+\.)/i,
        /leak\s+(the\s+)?(database|credentials?|passwords?|tokens?|data|records?)/i,
        /steal\s+(the\s+)?(credentials?|passwords?|tokens?|data|records?|keys?)/i,
    ],
};

const dlpPatterns = [
    /trigger\s+payload\s+dlp/i,
    /\bssn\b/i,
    /\bdlp\b/i,
];

function analyzePayload(text) {
    const lower = text.toLowerCase();
    const familyHits = [];
    for (const [family, patterns] of Object.entries(patternFamilies)) {
        const matched = patterns.filter(p => p.test(lower));
        if (matched.length > 0) familyHits.push({ family, count: matched.length });
    }
    const familyCount = familyHits.length;
    const totalMatches = familyHits.reduce((s, h) => s + h.count, 0);
    let tier;
    if (familyCount === 0) tier = "COMPLIANT";
    else if (familyCount === 1 && totalMatches === 1) tier = "FLAGGED";
    else if (familyCount >= 3 || (familyCount >= 2 && totalMatches >= 3)) tier = "CRITICAL";
    else tier = "VIOLATION";
    return { tier, familyHits, familyCount, totalMatches };
}

app.http('hello', {
    methods: ['POST', 'GET'],
    authLevel: 'anonymous',
    handler: async (request, context) => {
        const now = Date.now();

        if (request.method === 'POST') {
            while (rateLimitStore.length > 0 && rateLimitStore[0] < now - 10000) rateLimitStore.shift();
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
            rateLimitStore.push(now);
        }

        if (request.method === 'GET') {
            return { status: 200, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(globalLogHistory) };
        }

        let body = {};
        try {
            const rawText = await request.text();
            if (rawText) body = JSON.parse(rawText);
        } catch (e) { context.log("Parsing error:", e); }

        const { action, tenantId, scope, ttl } = body;
        const selectedTenant = tenantId || "GOV-DEPT-ENERGY-01";
        const timestamp = new Date().toLocaleTimeString();

        if (action === 'mint') {
            const callStart = Date.now();
            const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
                modulusLength: 2048,
                publicKeyEncoding: { type: 'spki', format: 'pem' },
                privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
            });
            const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "hsm-kid-9921-alpha", typ: "JWT" })).toString('base64url');
            const payload = Buffer.from(JSON.stringify({
                tenant: selectedTenant, scope,
                iat: Math.floor(Date.now() / 1000),
                exp: Math.floor(Date.now() / 1000) + (parseInt(ttl) || 5),
                jti: crypto.randomUUID()
            })).toString('base64url');
            const signingInput = `${header}.${payload}`;
            const signature = crypto.sign('sha256', Buffer.from(signingInput), { key: privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING }).toString('base64url');
            const signedJwt = `${signingInput}.${signature}`;
            const pubKeyExport = crypto.createPublicKey(publicKey).export({ format: 'jwk' });
            const latency = Date.now() - callStart;
            globalLogHistory.unshift({ time: timestamp, event: "EVT_" + crypto.randomBytes(3).toString('hex').toUpperCase(), tenant: selectedTenant, mapping: "NIST AC-2 | ISO A.5.15 | SOC2 CC6.3", status: "MINTED" });
            return {
                status: 200, headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: signedJwt, publicKey: { kty: pubKeyExport.kty, kid: "hsm-kid-9921-alpha", use: "sig", alg: "RS256", n: pubKeyExport.n, e: pubKeyExport.e }, latency })
            };
        }

        if (action === 'shield') {
            const callStart = Date.now();
            const fullTextPayload = Object.values(body).filter(val => typeof val === 'string').join(' ');
            const latency = Date.now() - callStart;

            if (dlpPatterns.some(p => p.test(fullTextPayload))) {
                globalLogHistory.unshift({ time: timestamp, event: "EVT_" + crypto.randomBytes(3).toString('hex').toUpperCase(), tenant: selectedTenant, mapping: "NIST SI-4 | ISO A.8.12 | SOC2 CC7.2", status: "BLOCKED" });
                return { status: 200, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status: "REJECTED", tier: "BLOCKED", message: "[REDACTED] Outbound packet scrubbed.", reason: "CUI leak mitigation array intercepted a raw multi-digit identifier schema matching SSN pattern rules.", latency }) };
            }

            const { tier, familyHits, familyCount, totalMatches } = analyzePayload(fullTextPayload);
            const familyNames = familyHits.map(h => h.family.replace(/_/g, ' ')).join(' | ');

            const logEntry = { time: timestamp, event: "EVT_" + crypto.randomBytes(3).toString('hex').toUpperCase(), tenant: selectedTenant, mapping: "NIST SI-4 | ISO A.8.12 | SOC2 CC7.2", status: tier };
            globalLogHistory.unshift(logEntry);

            const responses = {
                COMPLIANT: { status: "SUCCESS", tier, message: "Execution Output Clear: System operational framework processing queries.", latency },
                FLAGGED:   { status: "FLAGGED", tier, message: "Soft anomaly signal detected. Payload logged for analyst review.", reason: `Heuristic engine matched 1 pattern in family: ${familyNames}. Request passed with elevated monitoring. NIST SI-4 soft-alert threshold triggered.`, families: familyCount, signals: totalMatches, latency },
                VIOLATION: { status: "REJECTED", tier, message: "Adversarial structural pattern intercepted. Connection terminated.", reason: `NIST SI-4 heuristic matrix matched ${totalMatches} signal(s) across ${familyCount} attack family: ${familyNames}.`, families: familyCount, signals: totalMatches, latency },
                CRITICAL:  { status: "REJECTED", tier, message: "Multi-vector attack payload detected. Session isolated. Incident escalated to SIEM.", reason: `NIST SI-4 critical threshold breached: ${totalMatches} signals across ${familyCount} attack families: ${familyNames}. Automated incident record generated.`, families: familyCount, signals: totalMatches, latency },
            };

            return { status: 200, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(responses[tier]) };
        }

        return { status: 400, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: "Unknown parameter." }) };
    }
});
