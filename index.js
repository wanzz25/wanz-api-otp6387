const express = require('express');
const chalk = require('chalk');
const fs = require('fs');
const axios = require('axios');
const cors = require('cors');
const path = require('path');
const rateLimit = require('express-rate-limit');
require('dotenv').config();
// Env OTP/SMTP dibaca dari .env.otp (tidak menimpa nilai yang sudah ada di .env atau dashboard)
require('dotenv').config({ path: path.join(__dirname, '.env.otp'), quiet: true });
require('dotenv').config({ path: path.join(__dirname, '.env.ai'), quiet: true });

const settings = require('./settings');
const auth = require('./core/auth');
const cats = require('./core/categories');

const app = express();
const PORT = process.env.PORT || 3000;

app.enable("trust proxy");
app.set("json spaces", 2);
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cors());

const limiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 150,
  message: {
    creator: settings.creatorName || "wanz ai",
    status: false,
    message: "Terlalu banyak permintaan dari IP Anda, silakan coba lagi nanti."
  },
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false }
});
app.use(limiter);

app.use('/views', express.static(path.join(__dirname, 'views')));

global.getBuffer = async (url, options = {}) => {
  try {
    const res = await axios({
      method: 'get',
      url,
      headers: {
        'DNT': 1,
        'Upgrade-Insecure-Request': 1,
        'User-Agent': 'Mozilla/5.0'
      },
      ...options,
      responseType: 'arraybuffer'
    });
    return res.data;
  } catch (err) {
    return err;
  }
};

global.fetchJson = async (url, options = {}) => {
  try {
    const res = await axios({
      method: 'GET',
      url,
      headers: {
        'User-Agent': 'Mozilla/5.0'
      },
      ...options
    });
    return res.data;
  } catch (err) {
    return err;
  }
};

// Apikey user dicek di auth.apiGate; plugin lama hanya melihat key internal
global.apikey = [auth.INTERNAL_KEY];
global.totalreq = 0;

app.use((req, res, next) => {
  global.totalreq += 1;

  const originalJson = res.json;
  res.json = function (data) {
    if (
      data &&
      typeof data === 'object' &&
      req.path !== '/endpoints' &&
      req.path !== '/set'
    ) {
      return originalJson.call(this, {
        creator: settings.creatorName || "wanz ai",
        ...data
      });
    }
    return originalJson.call(this, data);
  };

  next();
});

app.get('/set', (req, res) => {
  const publicSettings = { ...settings };
  delete publicSettings.apiKeys;
  res.json(publicSettings);
});

app.get('/api/logo-proxy', (req, res) => {
  res.setHeader('Cache-Control', 'public, max-age=86400');
  return res.sendFile(path.join(__dirname, 'views', 'logo.png'));
});

// Login Google + gate apikey/limit harian untuk semua /api/*
app.use(auth.createRouter());
// Kunci kategori (default: AI). Diisi saat plugin dimuat; dicek sebelum apikey/limit.
const lockedCats = cats.getLockedSet(settings);
const lockedPaths = new Set();
app.use(cats.createLockGuard(lockedPaths, lockedCats));
app.use(auth.apiGate);

let totalRoutes = 0;
let totalLocked = 0;
let rawEndpoints = {};
const pluginFolder = path.join(__dirname, 'plugin');

if (!fs.existsSync(pluginFolder)) {
  fs.mkdirSync(pluginFolder);
}

fs.readdirSync(pluginFolder).forEach(file => {
  const fullPath = path.join(pluginFolder, file);
  if (file.endsWith('.js')) {
    try {
      const routes = require(fullPath);
      const handlers = Array.isArray(routes) ? routes : [routes];

      handlers.forEach(route => {
        const { name, desc, path: routePath, run } = route;
        const category = cats.normalizeCategory(route.category);

        if (name && desc && category && routePath && typeof run === 'function') {
          const cleanPath = routePath.split('?')[0];
          const locked = cats.isLocked(category, lockedCats);
          const listKey = locked ? cats.lockedLabel(category) : category;

          if (locked) {
            // Tidak didaftarkan sebagai route aktif; request akan ditolak 403 oleh lock guard
            lockedPaths.add(cleanPath.toLowerCase().replace(/\/+$/, ''));
            totalLocked++;
          } else {
            app.get(cleanPath, run);
            totalRoutes++;
            console.log(chalk.hex('#ff79c6')(`✔ Loaded Plugin Route: `) + chalk.hex('#f1fa8c')(`${cleanPath} (${file})`));
          }

          if (!rawEndpoints[listKey]) rawEndpoints[listKey] = [];
          rawEndpoints[listKey].push({
            name,
            desc: locked ? '[TERKUNCI] ' + desc : desc,
            path: routePath,
            cleanPath: cleanPath,
            ...(locked ? { locked: true } : {})
          });
        } else {
          console.warn(chalk.bgRed.white(` ⚠ Skipped invalid route in ${file}`));
        }
      });

    } catch (err) {
      console.error(chalk.bgRed.white(` ❌ Error in plugin ${file}: ${err.message}`));
    }
  }
});

const sortedEndpoints = Object.keys(rawEndpoints)
  .sort((a, b) => a.localeCompare(b))
  .reduce((sorted, category) => {
    sorted[category] = rawEndpoints[category].sort((a, b) => a.name.localeCompare(b.name));
    return sorted;
  }, {});

app.get('/endpoints', (req, res) => {
  res.json({
    total: totalRoutes,
    totalLocked: totalLocked,
    totalRequests: global.totalreq,
    endpoints: sortedEndpoints
  });
});

app.get('/', (req, res) => {
  try {
    res.sendFile(path.join(__dirname, 'views', 'index.html'));
  } catch (err) {
    res.status(500).send("Gagal memuat halaman utama: " + err.message);
  }
});

app.get('/playground', (req, res) => {
  try {
    res.sendFile(path.join(__dirname, 'views', 'playground.html'));
  } catch (err) {
    res.status(500).send("Gagal memuat halaman playground: " + err.message);
  }
});

app.get('/profile', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'profile.html'));
});

app.get('/dashboard', (req, res) => res.redirect(302, '/profile'));

app.get('/api', (req, res) => {
  try {
    res.sendFile(path.join(__dirname, 'views', 'api.html'));
  } catch (err) {
    res.status(500).send("Gagal memuat halaman API docs: " + err.message);
  }
});

app.get('/api/stats', (req, res) => {
  res.json({
    status: true,
    totalRequests: global.totalreq,
    totalEndpoints: totalRoutes,
    uptime: process.uptime()
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(chalk.bgHex('#ffb86c').black(` 🚀 SERVER IS RUNNING ON PORT ${PORT} `));
  console.log(chalk.bgHex('#50fa7b').black(` 📦 TOTAL ROUTES LOADED: ${totalRoutes} `));
});

module.exports = app;
