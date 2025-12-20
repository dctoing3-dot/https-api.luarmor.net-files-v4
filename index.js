// ============================================
// 🔺 ULTIMATE HUB - VERCEL SERVERLESS v4.0
// ============================================
// Pure serverless - NO EXPRESS
// ============================================

const https = require('https');
const crypto = require('crypto');

// ============================================
// 🔧 CONFIGURATION
// ============================================
const CONFIG = {
    LOADER_SCRIPT_URL: "https://raw.githubusercontent.com/trianaq765-cmd/lua-protector/refs/heads/main/Protected_8132419935440713.lua.txt",
    WORKINK_API: "https://work.ink/_api/v2/token/isValid/",
    
    RATE_LIMIT_WINDOW: 60 * 1000,
    RATE_LIMIT_MAX: 60,
    BLOCK_DURATION: 5 * 60 * 1000,
    MAX_FAILED_ATTEMPTS: 10,
    
    SCRIPT_CACHE_TTL: 10 * 60 * 1000,
    WORKINK_CACHE_TTL: 5 * 60 * 1000,
    
    VERSION: "4.0-VERCEL"
};

const MASTER_SECRET = process.env.MASTER_SECRET || crypto.randomBytes(64).toString('hex');

// ============================================
// 🎨 HTML TEMPLATE
// ============================================
const NOT_AUTHORIZED_HTML = `<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Unauthorized | Premium Protect</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
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
            position: relative; z-index: 10; height: 100vh;
            display: flex; flex-direction: column;
            justify-content: center; align-items: center;
            text-align: center; padding: 20px; user-select: none;
        }
        .auth-label {
            display: flex; align-items: center; gap: 12px;
            color: #ffffff; font-size: 1.1rem; font-weight: 600;
            letter-spacing: 3px; text-transform: uppercase; margin-bottom: 25px;
        }
        h1 {
            color: #ffffff; font-size: clamp(1.8rem, 5vw, 2.5rem);
            font-weight: 800; max-width: 700px;
            margin: 0 0 20px 0; line-height: 1.3;
            background: linear-gradient(180deg, #ffffff 40%, #94a3b8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        p { color: rgba(255, 255, 255, 0.4); font-size: 1.1rem; margin: 0; }
        .icon { font-size: 1.4rem; }
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
// 🔐 CRYPTO
// ============================================
function hashHWID(hwid) {
    return crypto.createHash('sha512').update(hwid + MASTER_SECRET).digest('hex');
}

// ============================================
// 🌐 HTTP HELPER
// ============================================
function httpsGet(url) {
    return new Promise((resolve, reject) => {
        https.get(url, { timeout: 15000 }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                if (res.statusCode === 200) {
                    resolve(data);
                } else {
                    reject(new Error(`HTTP ${res.statusCode}`));
                }
            });
        }).on('error', reject).on('timeout', () => reject(new Error('Timeout')));
    });
}

function httpsGetJSON(url) {
    return httpsGet(url).then(JSON.parse);
}

// ============================================
// 🛡️ HELPERS
// ============================================
function getRealIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
           req.headers['x-real-ip'] || 'unknown';
}

function isExecutor(req) {
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    const accept = req.headers['accept'] || '';
    
    if (req.headers['uh-executor'] || req.headers['x-executor']) return true;
    if (accept.includes('text/html') && ua.includes('mozilla')) return false;
    if (req.headers['sec-fetch-mode']) return false;
    
    return true;
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
        stores.failedAttempts.delete(ip);
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
        return { allowed: false, blocked: true };
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
    const cacheKey = `workink:${key}`;
    const now = Date.now();
    
    const cached = stores.workinkCache.get(cacheKey);
    if (cached && (now - cached.time < CONFIG.WORKINK_CACHE_TTL)) {
        return cached.valid;
    }
    
    try {
        const data = await httpsGetJSON(CONFIG.WORKINK_API + encodeURIComponent(key));
        const valid = data?.valid === true;
        stores.workinkCache.set(cacheKey, { valid, time: now });
        return valid;
    } catch (error) {
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
    } catch (error) {
        return stores.scriptCache.content || '-- Script temporarily unavailable\n-- Error: ' + error.message;
    }
}

// ============================================
// 📨 RESPONSE HELPERS
// ============================================
function sendJSON(res, data, status = 200) {
    res.status(status).json(data);
}

function sendHTML(res, html, status = 200) {
    res.status(status).setHeader('Content-Type', 'text/html').send(html);
}

function sendText(res, text, status = 200) {
    res.status(status).setHeader('Content-Type', 'text/plain; charset=utf-8').send(text);
}

// ============================================
// 🌐 MAIN HANDLER (Vercel Serverless Entry)
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
        return res.status(200).end();
    }
    
    // Security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Cache-Control', 'no-store');
    
    try {
        // ============================================
        // ROUTE: /health
        // ============================================
        if (path === '/health' || path === '/api/health') {
            return sendJSON(res, {
                status: 'ok',
                version: CONFIG.VERSION,
                cache: { script: !!stores.scriptCache.content },
                keys: stores.database.size,
                serverless: true
            });
        }
        
        // ============================================
        // ROUTE: / (root)
        // ============================================
        if (path === '/' || path === '/api' || path === '/api/') {
            if (!isExecutor(req)) {
                return sendHTML(res, NOT_AUTHORIZED_HTML, 401);
            }
            return sendJSON(res, { status: 'online', version: CONFIG.VERSION });
        }
        
        // ============================================
        // ROUTE: /script (and aliases)
        // ============================================
        if (['/script', '/api/script', '/loader', '/load', '/s'].includes(path)) {
            if (!isExecutor(req)) {
                return sendHTML(res, NOT_AUTHORIZED_HTML, 401);
            }
            
            const rateCheck = checkRateLimit(ip);
            if (!rateCheck.allowed) {
                if (rateCheck.warning) {
                    return sendJSON(res, { error: 'slow_down', warning: rateCheck.warning }, 429);
                }
                return sendJSON(res, { error: 'rate_limited', retryAfter: rateCheck.remaining || 300 }, 429);
            }
            
            const script = await getScript();
            return sendText(res, script);
        }
        
        // ============================================
        // ROUTE: /api/validate
        // ============================================
        if (path === '/api/validate' && method === 'POST') {
            const rateCheck = checkRateLimit(ip);
            if (!rateCheck.allowed) {
                return sendJSON(res, { error: 'rate_limited' }, 429);
            }
            
            const { key, hwid, userId, userName } = req.body || {};
            
            if (!validateKey(key)) {
                return sendJSON(res, { valid: false, error: 'invalid_key_format' });
            }
            
            if (!validateHWID(hwid)) {
                return sendJSON(res, { valid: false, error: 'invalid_hwid' });
            }
            
            const isValidKey = await validateWorkInk(key);
            
            if (isValidKey === null) {
                return sendJSON(res, { valid: false, error: 'validation_failed' });
            }
            
            if (!isValidKey) {
                if (stores.database.has(key)) {
                    stores.database.delete(key);
                }
                
                const attempts = (stores.failedAttempts.get(ip) || 0) + 1;
                stores.failedAttempts.set(ip, attempts);
                
                if (attempts >= CONFIG.MAX_FAILED_ATTEMPTS) {
                    stores.tempBlocks.set(ip, { until: Date.now() + CONFIG.BLOCK_DURATION });
                }
                
                return sendJSON(res, { valid: false, error: 'invalid_key' });
            }
            
            stores.failedAttempts.delete(ip);
            stores.warnings.delete(ip);
            
            const hashedHWID = hashHWID(hwid);
            const existing = stores.database.get(key);
            
            if (existing) {
                if (existing.hwid !== hashedHWID) {
                    return sendJSON(res, {
                        valid: false,
                        error: 'bound_to_other',
                        boundUser: existing.userName
                    });
                }
                
                existing.lastUsed = Date.now();
                existing.useCount = (existing.useCount || 0) + 1;
                stores.database.set(key, existing);
                
                return sendJSON(res, {
                    valid: true,
                    returning: true,
                    userName: existing.userName
                });
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
            
            return sendJSON(res, { valid: true, newBinding: true });
        }
        
        // ============================================
        // 404
        // ============================================
        if (!isExecutor(req)) {
            return sendHTML(res, NOT_AUTHORIZED_HTML, 404);
        }
        return sendJSON(res, { error: 'not_found' }, 404);
        
    } catch (error) {
        console.error('Error:', error);
        return sendJSON(res, { error: 'server_error', message: error.message }, 500);
    }
};