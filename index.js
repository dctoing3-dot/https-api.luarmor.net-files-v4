const https = require('https');
const crypto = require('crypto');

// ============================================
// 🔧 CONFIGURATION
// ============================================
const CONFIG = {
    LOADER_SCRIPT_URL: "https://raw.githubusercontent.com/trianaq765-cmd/lua-protector/refs/heads/main/Protected_8132419935440713.lua.txt",
    WORKINK_API: "https://work.ink/_api/v2/token/isValid/",
    RATE_LIMIT_WINDOW: 60000,
    RATE_LIMIT_MAX: 60,
    BLOCK_DURATION: 300000,
    MAX_FAILED_ATTEMPTS: 10,
    SCRIPT_CACHE_TTL: 600000,
    WORKINK_CACHE_TTL: 300000,
    VERSION: "4.0-VERCEL"
};

const MASTER_SECRET = process.env.MASTER_SECRET || crypto.randomBytes(64).toString('hex');

// ============================================
// 🎨 HTML TEMPLATE (SAMA PERSIS!)
// ============================================
const NOT_AUTHORIZED_HTML = `<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Unauthorized | Premium Protect</title>
    <style>
        * {
            margin: 0; padding: 0; box-sizing: border-box;
        }

        body, html {
            width: 100%; height: 100%; overflow: hidden;
            background-color: #000000;
            font-family: 'Inter', -apple-system, sans-serif;
            color: #ffffff;
        }

        .bg-layer {
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: linear-gradient(270deg, #000000, #0f172a, #000000);
            background-size: 600% 600%;
            animation: gradientShift 30s ease infinite;
            z-index: 1;
        }

        .container {
            position: relative;
            z-index: 10;
            height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            text-align: center;
            padding: 20px;
            user-select: none;
        }

        .auth-label {
            display: flex;
            align-items: center;
            gap: 12px;
            color: #ffffff;
            font-size: 1.1rem;
            font-weight: 600;
            letter-spacing: 3px;
            text-transform: uppercase;
            margin-bottom: 25px;
        }

        h1 {
            color: #ffffff;
            font-size: clamp(1.8rem, 5vw, 2.5rem);
            font-weight: 800;
            max-width: 700px;
            margin: 0 0 20px 0;
            line-height: 1.3;
            background: linear-gradient(180deg, #ffffff 40%, #94a3b8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        p {
            color: rgba(255, 255, 255, 0.4);
            font-size: 1.1rem;
            margin: 0;
        }

        .icon {
            font-size: 1.4rem;
        }

        @keyframes gradientShift {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
    </style>
</head>
<body>
    <div class="bg-layer"></div>

    <div class="container">
        <div class="auth-label">
            <span class="icon">⛔</span>
            Not Authorized
            <span class="icon">⛔</span>
        </div>

        <h1>You are not allowed to view these files.</h1>
        <p>Close this page & proceed.</p>
    </div>
</body>
</html>`;

// ============================================
// 📦 IN-MEMORY STORES
// ============================================
const stores = {
    database: new Map(),
    rateLimits: new Map(),
    tempBlocks: new Map(),
    failedAttempts: new Map(),
    warnings: new Map(),
    workinkCache: new Map(),
    scriptCache: { content: null, time: 0 }
};

// ============================================
// 🌐 HTTP HELPERS
// ============================================
function httpsGet(url) {
    return new Promise((resolve, reject) => {
        https.get(url, { timeout: 15000 }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                if (res.statusCode === 200) resolve(data);
                else reject(new Error('HTTP ' + res.statusCode));
            });
        }).on('error', reject).on('timeout', () => reject(new Error('Timeout')));
    });
}

// ============================================
// 🛡️ HELPERS
// ============================================
function getRealIP(req) {
    const fwd = req.headers['x-forwarded-for'];
    return fwd ? fwd.split(',')[0].trim() : 'unknown';
}

function isExecutor(req) {
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    const accept = req.headers['accept'] || '';
    if (accept.includes('text/html') && ua.includes('mozilla')) return false;
    if (req.headers['sec-fetch-mode']) return false;
    return true;
}

function hashHWID(hwid) {
    return crypto.createHash('sha512').update(hwid + MASTER_SECRET).digest('hex');
}

// ============================================
// 🚦 RATE LIMITER
// ============================================
function checkRateLimit(ip) {
    const now = Date.now();
    const blockInfo = stores.tempBlocks.get(ip);
    
    if (blockInfo && blockInfo.until > now) {
        return { allowed: false, remaining: Math.ceil((blockInfo.until - now) / 1000) };
    } else if (blockInfo) {
        stores.tempBlocks.delete(ip);
        stores.warnings.delete(ip);
    }
    
    let rateInfo = stores.rateLimits.get(ip);
    if (!rateInfo || rateInfo.resetAt < now) {
        rateInfo = { count: 1, resetAt: now + CONFIG.RATE_LIMIT_WINDOW };
    } else {
        rateInfo.count++;
    }
    stores.rateLimits.set(ip, rateInfo);
    
    if (rateInfo.count > CONFIG.RATE_LIMIT_MAX) {
        const warnings = stores.warnings.get(ip) || 0;
        if (warnings < 2) {
            stores.warnings.set(ip, warnings + 1);
            return { allowed: false, warning: warnings + 1 };
        }
        stores.tempBlocks.set(ip, { until: now + CONFIG.BLOCK_DURATION });
        return { allowed: false, remaining: 300 };
    }
    return { allowed: true };
}

// ============================================
// 🔧 VALIDATORS
// ============================================
function validateKey(key) {
    return key && typeof key === 'string' && key.length >= 5 && key.length <= 100 && /^[a-zA-Z0-9\-_]+$/.test(key);
}

function validateHWID(hwid) {
    return hwid && typeof hwid === 'string' && hwid.length >= 10 && hwid.length <= 300;
}

function sanitize(str, maxLen = 100) {
    return typeof str === 'string' ? str.replace(/[<>\"'&\x00-\x1f]/g, '').substring(0, maxLen).trim() : '';
}

// ============================================
// 🔑 WORK.INK VALIDATION
// ============================================
async function validateWorkInk(key) {
    const cacheKey = 'wk:' + key;
    const now = Date.now();
    const cached = stores.workinkCache.get(cacheKey);
    
    if (cached && (now - cached.time < CONFIG.WORKINK_CACHE_TTL)) {
        return cached.valid;
    }
    
    try {
        const data = await httpsGet(CONFIG.WORKINK_API + encodeURIComponent(key));
        const json = JSON.parse(data);
        const valid = json.valid === true;
        stores.workinkCache.set(cacheKey, { valid, time: now });
        return valid;
    } catch (e) {
        return cached ? cached.valid : null;
    }
}

// ============================================
// 📦 SCRIPT CACHE
// ============================================
async function getScript() {
    const now = Date.now();
    if (stores.scriptCache.content && (now - stores.scriptCache.time < CONFIG.SCRIPT_CACHE_TTL)) {
        return stores.scriptCache.content;
    }
    try {
        const content = await httpsGet(CONFIG.LOADER_SCRIPT_URL);
        stores.scriptCache.content = content;
        stores.scriptCache.time = now;
        return content;
    } catch (e) {
        return stores.scriptCache.content || '-- Script temporarily unavailable';
    }
}

// ============================================
// 🌐 MAIN HANDLER
// ============================================
module.exports = async (req, res) => {
    const path = req.url || '/';
    const method = req.method;
    const ip = getRealIP(req);
    
    // CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    if (method === 'OPTIONS') {
        res.status(200).end();
        return;
    }
    
    // Security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Cache-Control', 'no-store');
    
    // ============================================
    // ROUTES
    // ============================================
    
    // /health
    if (path === '/api' || path === '/api/' || path === '/api/health' || path === '/health') {
        res.status(200).json({
            status: 'ok',
            version: CONFIG.VERSION,
            cache: { script: !!stores.scriptCache.content },
            keys: stores.database.size
        });
        return;
    }
    
    // /script
    if (path === '/api/script' || path === '/script' || path === '/s' || path === '/loader' || path === '/load') {
        if (!isExecutor(req)) {
            res.setHeader('Content-Type', 'text/html');
            res.status(401).end(NOT_AUTHORIZED_HTML);
            return;
        }
        
        const rateCheck = checkRateLimit(ip);
        if (!rateCheck.allowed) {
            res.status(429).json({ error: 'rate_limited', retryAfter: rateCheck.remaining || 300 });
            return;
        }
        
        const script = await getScript();
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.status(200).end(script);
        return;
    }
    
    // /api/validate
    if ((path === '/api/validate' || path === '/validate') && method === 'POST') {
        const rateCheck = checkRateLimit(ip);
        if (!rateCheck.allowed) {
            res.status(429).json({ error: 'rate_limited' });
            return;
        }
        
        try {
            const body = req.body || {};
            const { key, hwid, userId, userName } = body;
            
            if (!validateKey(key)) {
                res.status(200).json({ valid: false, error: 'invalid_key_format' });
                return;
            }
            
            if (!validateHWID(hwid)) {
                res.status(200).json({ valid: false, error: 'invalid_hwid' });
                return;
            }
            
            const isValidKey = await validateWorkInk(key);
            
            if (isValidKey === null) {
                res.status(200).json({ valid: false, error: 'validation_failed' });
                return;
            }
            
            if (!isValidKey) {
                stores.database.delete(key);
                const attempts = (stores.failedAttempts.get(ip) || 0) + 1;
                stores.failedAttempts.set(ip, attempts);
                if (attempts >= CONFIG.MAX_FAILED_ATTEMPTS) {
                    stores.tempBlocks.set(ip, { until: Date.now() + CONFIG.BLOCK_DURATION });
                }
                res.status(200).json({ valid: false, error: 'invalid_key' });
                return;
            }
            
            stores.failedAttempts.delete(ip);
            stores.warnings.delete(ip);
            
            const hashedHWID = hashHWID(hwid);
            const existing = stores.database.get(key);
            
            if (existing) {
                if (existing.hwid !== hashedHWID) {
                    res.status(200).json({ valid: false, error: 'bound_to_other', boundUser: existing.userName });
                    return;
                }
                existing.lastUsed = Date.now();
                existing.useCount = (existing.useCount || 0) + 1;
                stores.database.set(key, existing);
                res.status(200).json({ valid: true, returning: true, userName: existing.userName });
                return;
            }
            
            stores.database.set(key, {
                hwid: hashedHWID,
                userId: sanitize(String(userId || ''), 20),
                userName: sanitize(String(userName || 'Unknown'), 50),
                boundAt: Date.now(),
                lastUsed: Date.now(),
                useCount: 1,
                boundIP: ip
            });
            
            res.status(200).json({ valid: true, newBinding: true });
            return;
            
        } catch (e) {
            res.status(200).json({ valid: false, error: 'server_error' });
            return;
        }
    }
    
    // 404 / Root
    if (!isExecutor(req)) {
        res.setHeader('Content-Type', 'text/html');
        res.status(404).end(NOT_AUTHORIZED_HTML);
        return;
    }
    
    res.status(404).json({ error: 'not_found' });
};