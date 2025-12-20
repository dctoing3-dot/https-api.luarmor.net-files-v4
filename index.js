// ============================================
// 🔺 ULTIMATE HUB - VERCEL SERVERLESS v4.0
// ============================================
// SAMA PERSIS dengan Render version
// - Semua fitur keamanan lengkap
// - HTML Not Authorized tidak berubah
// - Rate limiting, HWID binding, Work.ink cache
// ============================================

import https from 'https';
import crypto from 'crypto';

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
// 🎨 HTML TEMPLATE (SAMA PERSIS - TIDAK BERUBAH!)
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
// 📦 IN-MEMORY STORES (SAMA SEPERTI RENDER)
// ============================================
class LimitedMap extends Map {
    constructor(maxSize = 10000) {
        super();
        this.maxSize = maxSize;
    }
    set(key, value) {
        if (this.size >= this.maxSize) {
            const firstKey = this.keys().next().value;
            this.delete(firstKey);
        }
        return super.set(key, value);
    }
}

const stores = {
    database: new LimitedMap(5000),
    rateLimits: new LimitedMap(5000),
    tempBlocks: new LimitedMap(1000),
    failedAttempts: new LimitedMap(2000),
    warnings: new LimitedMap(2000),
    workinkCache: new LimitedMap(5000),
};

// Script Cache
const scriptCache = {
    content: null,
    checksum: null,
    lastFetch: 0,
    fetching: false,
    
    isValid() {
        return this.content && (Date.now() - this.lastFetch < CONFIG.SCRIPT_CACHE_TTL);
    },
    
    async refresh(force = false) {
        if (this.fetching) return this.content;
        if (!force && this.isValid()) return this.content;
        
        this.fetching = true;
        
        try {
            console.log('[CACHE] 🔄 Fetching script from GitHub...');
            const content = await httpsGet(CONFIG.LOADER_SCRIPT_URL);
            
            this.content = content;
            this.checksum = crypto.createHash('sha256').update(content).digest('hex').slice(0, 16);
            this.lastFetch = Date.now();
            
            console.log(`[CACHE] ✅ Script cached (${content.length} bytes, checksum: ${this.checksum})`);
            
            return this.content;
        } catch (error) {
            console.error('[CACHE] ❌ Fetch failed:', error.message);
            return this.content;
        } finally {
            this.fetching = false;
        }
    },
    
    get() {
        return {
            content: this.content,
            checksum: this.checksum,
            cached: this.isValid()
        };
    }
};

// ============================================
// 🌐 HTTP HELPERS
// ============================================
function httpsGet(url) {
    return new Promise((resolve, reject) => {
        const req = https.get(url, { timeout: 15000 }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                if (res.statusCode === 200) {
                    resolve(data);
                } else {
                    reject(new Error(`HTTP ${res.statusCode}`));
                }
            });
        });
        req.on('error', reject);
        req.on('timeout', () => {
            req.destroy();
            reject(new Error('Timeout'));
        });
    });
}

function httpsGetJSON(url) {
    return httpsGet(url).then(data => JSON.parse(data));
}

// ============================================
// 🔐 CRYPTO (SAMA SEPERTI RENDER)
// ============================================
function hashHWID(hwid) {
    return crypto.createHash('sha512').update(hwid + MASTER_SECRET).digest('hex');
}

// ============================================
// 📝 LOGGER (SAMA SEPERTI RENDER)
// ============================================
function log(event, data, level = 'info') {
    const colors = { info: '\x1b[36m', warning: '\x1b[33m', error: '\x1b[31m', success: '\x1b[32m' };
    console.log(`${colors[level] || colors.info}[${level.toUpperCase()}]\x1b[0m ${event}:`, JSON.stringify(data));
}

// ============================================
// 🛡️ HELPERS (SAMA SEPERTI RENDER)
// ============================================
function getRealIP(req) {
    const forwarded = req.headers['x-forwarded-for'];
    const ip = forwarded?.split(',')[0]?.trim() || 
               req.headers['x-real-ip'] || 
               req.socket?.remoteAddress ||
               'unknown';
    return ip === '::1' ? '127.0.0.1' : ip.replace('::ffff:', '');
}

function isExecutor(req) {
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    const accept = req.headers['accept'] || '';
    
    if (req.headers['uh-executor'] || req.headers['x-executor']) return true;
    if (accept.includes('text/html') && ua.includes('mozilla')) return false;
    if (req.headers['sec-fetch-mode']) return false;
    if (ua.includes('roblox') || ua.includes('synapse') || ua.includes('krnl')) return true;
    
    return true;
}

// ============================================
// 🚦 RATE LIMITER (SAMA SEPERTI RENDER)
// ============================================
function checkRateLimit(ip) {
    const now = Date.now();
    
    // Check temp block
    const blockInfo = stores.tempBlocks.get(ip);
    if (blockInfo && blockInfo.until > now) {
        const remaining = Math.ceil((blockInfo.until - now) / 1000);
        return { allowed: false, blocked: true, remaining };
    } else if (blockInfo) {
        stores.tempBlocks.delete(ip);
        stores.warnings.delete(ip);
        stores.failedAttempts.delete(ip);
    }
    
    // Check rate
    const key = `${ip}:normal`;
    let rateInfo = stores.rateLimits.get(key);
    
    if (!rateInfo || rateInfo.resetAt < now) {
        rateInfo = { count: 1, resetAt: now + CONFIG.RATE_LIMIT_WINDOW };
    } else {
        rateInfo.count++;
    }
    
    stores.rateLimits.set(key, rateInfo);
    
    if (rateInfo.count > CONFIG.RATE_LIMIT_MAX) {
        const warnings = stores.warnings.get(ip) || 0;
        
        if (warnings < 2) {
            stores.warnings.set(ip, warnings + 1);
            return { allowed: false, warning: warnings + 1 };
        }
        
        stores.tempBlocks.set(ip, { until: now + CONFIG.BLOCK_DURATION, reason: 'rate_limit' });
        return { allowed: false, blocked: true, remaining: 300 };
    }
    
    return { allowed: true };
}

// ============================================
// 🔧 VALIDATORS (SAMA SEPERTI RENDER)
// ============================================
const Validator = {
    key: (key) => key && typeof key === 'string' && key.length >= 5 && key.length <= 100 && /^[a-zA-Z0-9\-_]+$/.test(key),
    hwid: (hwid) => hwid && typeof hwid === 'string' && hwid.length >= 10 && hwid.length <= 300,
    sanitize: (str, maxLen = 100) => typeof str === 'string' ? str.replace(/[<>\"'&\x00-\x1f]/g, '').substring(0, maxLen).trim() : ''
};

// ============================================
// 🔑 WORK.INK VALIDATION (SAMA SEPERTI RENDER)
// ============================================
async function validateWorkInk(key, ip) {
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
        log('WORKINK_ERROR', { ip, error: error.message }, 'warning');
        return cached ? cached.valid : null;
    }
}

// ============================================
// 📨 RESPONSE HELPERS
// ============================================
function sendJSON(res, data, status = 200) {
    res.setHeader('Content-Type', 'application/json');
    res.status(status).end(JSON.stringify(data));
}

function sendHTML(res, html, status = 200) {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.status(status).end(html);
}

function sendText(res, text, status = 200) {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(status).end(text);
}

// ============================================
// 📍 ROUTE HANDLERS (SAMA SEPERTI RENDER)
// ============================================

// Health Check
async function handleHealth(req, res) {
    return sendJSON(res, {
        status: 'ok',
        version: CONFIG.VERSION,
        cache: { script: scriptCache.isValid() },
        keys: stores.database.size,
        serverless: true
    });
}

// Root
async function handleRoot(req, res) {
    if (!isExecutor(req)) {
        return sendHTML(res, NOT_AUTHORIZED_HTML, 401);
    }
    return sendJSON(res, { status: 'online', version: CONFIG.VERSION });
}

// Script Loader
async function handleScript(req, res, ip) {
    if (!isExecutor(req)) {
        log('BROWSER_ACCESS', { ip }, 'warning');
        return sendHTML(res, NOT_AUTHORIZED_HTML, 401);
    }
    
    // Rate limit
    const rateCheck = checkRateLimit(ip);
    if (!rateCheck.allowed) {
        if (rateCheck.warning) {
            return sendJSON(res, { error: 'slow_down', warning: rateCheck.warning }, 429);
        }
        return sendJSON(res, { error: 'rate_limited', retryAfter: rateCheck.remaining || 300 }, 429);
    }
    
    try {
        let cached = scriptCache.get();
        
        if (!cached.content) {
            await scriptCache.refresh(true);
            cached = scriptCache.get();
            if (!cached.content) {
                throw new Error('Script unavailable');
            }
        }
        
        // Refresh in background if stale
        if (!cached.cached) {
            scriptCache.refresh();
        }
        
        res.setHeader('X-Checksum', cached.checksum || 'none');
        res.setHeader('Cache-Control', 'no-store');
        return sendText(res, cached.content);
        
    } catch (error) {
        log('SCRIPT_ERROR', { ip, error: error.message }, 'error');
        return sendText(res, '-- Script temporarily unavailable\n-- Error: ' + error.message);
    }
}

// Validate Key
async function handleValidate(req, res, ip) {
    // Rate limit
    const rateCheck = checkRateLimit(ip);
    if (!rateCheck.allowed) {
        return sendJSON(res, { error: 'rate_limited' }, 429);
    }
    
    try {
        const { key, hwid, userId, userName } = req.body || {};
        
        if (!Validator.key(key)) {
            return sendJSON(res, { valid: false, error: 'invalid_key_format' });
        }
        
        if (!Validator.hwid(hwid)) {
            return sendJSON(res, { valid: false, error: 'invalid_hwid' });
        }
        
        // Validate with Work.ink
        const isValidKey = await validateWorkInk(key, ip);
        
        if (isValidKey === null) {
            return sendJSON(res, { valid: false, error: 'validation_failed', message: 'Cannot verify key' });
        }
        
        if (!isValidKey) {
            if (stores.database.has(key)) {
                stores.database.delete(key);
            }
            
            const attempts = (stores.failedAttempts.get(ip) || 0) + 1;
            stores.failedAttempts.set(ip, attempts);
            
            if (attempts >= CONFIG.MAX_FAILED_ATTEMPTS) {
                stores.tempBlocks.set(ip, { until: Date.now() + CONFIG.BLOCK_DURATION, reason: 'invalid_keys' });
            }
            
            return sendJSON(res, { valid: false, error: 'invalid_key' });
        }
        
        // Valid key - reset failed attempts
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
            
            // Update usage
            existing.lastUsed = Date.now();
            existing.useCount = (existing.useCount || 0) + 1;
            stores.database.set(key, existing);
            
            log('KEY_VALIDATED', { ip, key: key.slice(0, 8) + '...' }, 'success');
            
            return sendJSON(res, {
                valid: true,
                returning: true,
                userName: existing.userName
            });
        }
        
        // New binding
        stores.database.set(key, {
            hwid: hashedHWID,
            userId: Validator.sanitize(String(userId || ''), 20),
            userName: Validator.sanitize(String(userName || 'Unknown'), 50),
            boundAt: Date.now(),
            lastUsed: Date.now(),
            useCount: 1,
            boundIP: ip
        });
        
        log('KEY_BOUND', { ip, key: key.slice(0, 8) + '...' }, 'success');
        
        return sendJSON(res, { valid: true, newBinding: true });
        
    } catch (error) {
        log('VALIDATE_ERROR', { ip, error: error.message }, 'error');
        return sendJSON(res, { valid: false, error: 'server_error' });
    }
}

// 404 Handler
async function handle404(req, res) {
    if (!isExecutor(req)) {
        return sendHTML(res, NOT_AUTHORIZED_HTML, 404);
    }
    return sendJSON(res, { error: 'not_found' }, 404);
}

// ============================================
// 🌐 MAIN HANDLER (Vercel Entry Point)
// ============================================
export default async function handler(req, res) {
    // Parse URL
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const path = url.pathname;
    const method = req.method;
    const ip = getRealIP(req);
    
    // CORS Headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, UH-Executor, X-Executor');
    
    if (method === 'OPTIONS') {
        return res.status(200).end();
    }
    
    // Security Headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    
    try {
        // Route matching
        if (path === '/health' || path === '/api/health') {
            return await handleHealth(req, res);
        }
        
        if (path === '/' || path === '/api' || path === '/api/') {
            return await handleRoot(req, res);
        }
        
        if (['/script', '/api/script', '/loader', '/load', '/s'].includes(path)) {
            return await handleScript(req, res, ip);
        }
        
        if ((path === '/api/validate' || path === '/validate') && method === 'POST') {
            return await handleValidate(req, res, ip);
        }
        
        // 404
        return await handle404(req, res);
        
    } catch (error) {
        console.error('Handler error:', error);
        return sendJSON(res, { error: 'server_error', message: error.message }, 500);
    }
}

// ============================================
// 🧹 CLEANUP (Auto-runs periodically)
// ============================================
setInterval(() => {
    const now = Date.now();
    
    // Clean expired blocks
    for (const [ip, info] of stores.tempBlocks) {
        if (info.until < now) {
            stores.tempBlocks.delete(ip);
            stores.warnings.delete(ip);
            stores.failedAttempts.delete(ip);
        }
    }
    
    // Clean old rate limits
    for (const [key, info] of stores.rateLimits) {
        if (info.resetAt < now) {
            stores.rateLimits.delete(key);
        }
    }
    
    // Clean old workink cache
    for (const [key, info] of stores.workinkCache) {
        if (now - info.time > CONFIG.WORKINK_CACHE_TTL * 2) {
            stores.workinkCache.delete(key);
        }
    }
}, 60 * 1000);

// Pre-cache script on cold start
scriptCache.refresh(true);

console.log(`[VERCEL] 🔺 Ultimate Hub ${CONFIG.VERSION} initialized`);