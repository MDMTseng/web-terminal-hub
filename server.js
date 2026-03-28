const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const pty = require('node-pty');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');


// ========== Logging System ==========
const LOG_DIR = path.join(__dirname, 'logs');
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });

let _lastLogDate = '';
function getLogFileName() {
  const d = new Date();
  const dateStr = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
  if (dateStr !== _lastLogDate) {
    _lastLogDate = dateStr;
    _logSizeExceeded = false; // reset cap on new day
  }
  return `hub-${dateStr}.log`;
}

function timestamp() {
  return new Date().toISOString();
}

const MAX_LOG_SIZE = 10 * 1024 * 1024; // 10MB per log file
let _logSizeExceeded = false;

function writeLog(level, category, message, extra) {
  const ts = timestamp();
  const line = extra
    ? `[${ts}] [${level}] [${category}] ${message} | ${JSON.stringify(extra)}`
    : `[${ts}] [${level}] [${category}] ${message}`;

  // Console output — only errors/warnings/fatal + startup messages
  try {
    if (level === 'ERROR' || level === 'FATAL' || level === 'WARN' || category === 'server' || category === 'auth') {
      const stream = (level === 'ERROR' || level === 'FATAL') ? process.stderr : process.stdout;
      stream.write(line + '\n');
    }
  } catch (_) {}

  // File output (skip if log file already exceeded size cap, except errors)
  try {
    const logPath = path.join(LOG_DIR, getLogFileName());
    if (_logSizeExceeded && level !== 'ERROR' && level !== 'FATAL' && level !== 'WARN') return;
    fs.appendFileSync(logPath, line + '\n');
    // Check size periodically (every ~100 writes via WARN/ERROR or occasional INFO)
    if (level === 'WARN' || level === 'ERROR') {
      const stat = fs.statSync(logPath);
      _logSizeExceeded = stat.size > MAX_LOG_SIZE;
    }
  } catch (_) {}
}

const log = {
  info:  (cat, msg, extra) => writeLog('INFO',  cat, msg, extra),
  warn:  (cat, msg, extra) => writeLog('WARN',  cat, msg, extra),
  error: (cat, msg, extra) => writeLog('ERROR', cat, msg, extra),
  fatal: (cat, msg, extra) => writeLog('FATAL', cat, msg, extra),
};

// ========== Global Error Handlers ==========
process.on('uncaughtException', (err) => {
  // Ignore EPIPE errors (broken stdout/stderr pipe) to prevent infinite loop
  if (err.code === 'EPIPE' || err.code === 'ERR_STREAM_DESTROYED') return;
  try {
    log.fatal('process', `Uncaught Exception: ${err.message}`, { stack: err.stack });
  } catch (_) { /* prevent recursive crash if logging fails */ }
});

process.on('unhandledRejection', (reason, promise) => {
  const msg = reason instanceof Error ? reason.message : String(reason);
  const stack = reason instanceof Error ? reason.stack : undefined;
  log.error('process', `Unhandled Rejection: ${msg}`, { stack });
});

const app = express();
const PORT = process.env.HUB_PORT || 9091;

// ========== Groups config ==========
let groupsConfig = [];
try {
  const raw = fs.readFileSync(path.join(__dirname, 'groups.json'), 'utf-8');
  groupsConfig = JSON.parse(raw).groups || [];
  log.info('groups', `Loaded ${groupsConfig.length} groups: ${groupsConfig.map(g => g.name).join(', ')}`);
} catch (err) {
  log.error('groups', `Failed to load groups.json, using defaults: ${err.message}`);
  groupsConfig = [
    { name: 'Dev', icon: '🛠', color: '#64ffda', maxTerminals: 10 },
    { name: 'Ops', icon: '🖥', color: '#f78c6c', maxTerminals: 10 }
  ];
}

const GROUPS_FILE = path.join(__dirname, 'groups.json');

function saveGroups() {
  fs.writeFileSync(GROUPS_FILE, JSON.stringify({ groups: groupsConfig }, null, 2), 'utf-8');
  log.info('groups', `Saved ${groupsConfig.length} groups to groups.json`);
}

// ========== Master Password Config ==========
const AUTH_FILE = path.join(__dirname, 'auth.json');
let authConfig = { passwordHash: null, masterTokens: [] };

function loadAuthConfig() {
  try {
    const raw = fs.readFileSync(AUTH_FILE, 'utf-8');
    authConfig = JSON.parse(raw);
    if (!authConfig.masterTokens) authConfig.masterTokens = [];
    log.info('auth', `Master password configured: ${authConfig.passwordHash ? 'YES' : 'NO'}`);
  } catch (err) {
    log.info('auth', 'No auth.json found — master password not set.');
    authConfig = { passwordHash: null, masterTokens: [] };
  }
}

function saveAuthConfig() {
  fs.writeFileSync(AUTH_FILE, JSON.stringify(authConfig, null, 2), 'utf-8');
}

loadAuthConfig();

// ========== Password hashing utilities (crypto.scrypt, zero deps) ==========
const { scrypt, randomBytes, createHash, timingSafeEqual } = crypto;

function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = randomBytes(16).toString('hex');
    scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(`scrypt:${salt}:${derivedKey.toString('hex')}`);
    });
  });
}

function verifyPassword(password, storedHash) {
  return new Promise((resolve, reject) => {
    const [, salt, keyHex] = storedHash.split(':');
    const keyBuffer = Buffer.from(keyHex, 'hex');
    scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(timingSafeEqual(keyBuffer, derivedKey));
    });
  });
}

function hashMasterToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

function isValidMasterToken(token) {
  if (!token) return false;
  const tokenH = hashMasterToken(token);
  return authConfig.masterTokens.some(t => t.tokenHash === tokenH);
}

// ========== Auth: per-group latest-login-wins ==========
// Each group has its own active token. Logging into "Dev" only kicks previous "Dev" session.
const groupTokens = new Map(); // groupName -> { token, created }

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function getGroupForToken(token) {
  if (!token) return null;
  for (const [groupName, info] of groupTokens) {
    if (info.token === token) return groupName;
  }
  return null;
}

function isValidToken(token) {
  return getGroupForToken(token) !== null;
}

// Auth middleware — skip for welcome page, API endpoints that don't need auth
function authMiddleware(req, res, next) {
  // Allow welcome page and its assets
  if (req.path === '/welcome' || req.path === '/welcome.html' || req.path === '/login' || req.path === '/login.html') {
    return next();
  }
  // Allow group APIs (login, list/manage groups)
  if (req.path === '/api/login' || req.path === '/api/groups' || req.path.startsWith('/api/groups/')) {
    return next();
  }
  // Allow static assets (css, fonts)
  if (req.path === '/style.css') {
    return next();
  }

  const token = req.cookies?.token || req.headers['x-token'] || req.query.token;
  if (!isValidToken(token)) {
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Unauthorized. Please select a group.' });
    }
    return res.redirect('/welcome');
  }

  // Attach group info to request
  req.group = getGroupForToken(token);
  next();
}

// Simple cookie parser
app.use((req, res, next) => {
  req.cookies = {};
  const cookieHeader = req.headers.cookie;
  if (cookieHeader) {
    cookieHeader.split(';').forEach(c => {
      const [key, ...val] = c.trim().split('=');
      req.cookies[key.trim()] = val.join('=').trim();
    });
  }
  next();
});

app.use(express.json({ limit: '5mb' }));

// ========== Request Logging Middleware ==========
// Noisy polling endpoints — only log on error (4xx/5xx)
const QUIET_ROUTES = new Set(['/api/groups', '/api/terminals', '/api/platform', '/api/group-info']);

app.use((req, res, next) => {
  const start = Date.now();
  const originalEnd = res.end;
  res.end = function(...args) {
    const duration = Date.now() - start;
    const status = res.statusCode;
    // Only log API requests and errors (skip static assets to reduce noise)
    if (req.path.startsWith('/api/') || status >= 400) {
      // Skip successful polling endpoints to save disk I/O
      if (status < 400 && QUIET_ROUTES.has(req.path)) {
        originalEnd.apply(this, args);
        return;
      }
      const level = status >= 500 ? 'error' : status >= 400 ? 'warn' : 'info';
      log[level]('http', `${req.method} ${req.path} → ${status} (${duration}ms)`, {
        ip: req.ip || req.connection?.remoteAddress,
        query: Object.keys(req.query).length ? req.query : undefined,
      });
    }
    originalEnd.apply(this, args);
  };
  next();
});

// ========== Master Auth Middleware ==========
function masterAuthMiddleware(req, res, next) {
  // Always allow: login page, master auth APIs, static assets
  if (req.path === '/login' || req.path === '/login.html' ||
      req.path === '/api/master-status' || req.path === '/api/master-login' ||
      req.path === '/api/master-setup' || req.path === '/style.css') {
    return next();
  }

  // If no master password is configured, redirect to login for setup
  if (!authConfig.passwordHash) {
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Master password not set. Visit /login to set up.' });
    }
    return res.redirect('/login');
  }

  // Check for master_token cookie
  const masterToken = req.cookies?.master_token;
  if (isValidMasterToken(masterToken)) {
    return next();
  }

  // Not authenticated with master password
  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: 'Master password required.' });
  }
  return res.redirect('/login');
}

app.use(masterAuthMiddleware);

// ========== Master Password API ==========
app.get('/api/master-status', (req, res) => {
  res.json({ hasPassword: !!authConfig.passwordHash });
});

app.post('/api/master-setup', async (req, res) => {
  // Only works if no password is set yet
  if (authConfig.passwordHash) {
    return res.status(403).json({ error: 'Password already set.' });
  }

  const { password } = req.body;
  if (!password || password.length < 4) {
    return res.status(400).json({ error: 'Password must be at least 4 characters.' });
  }

  authConfig.passwordHash = await hashPassword(password);
  authConfig.masterTokens = [];

  // Auto-login: generate and set token
  const rawToken = randomBytes(32).toString('hex');
  authConfig.masterTokens.push({
    tokenHash: hashMasterToken(rawToken),
    created: new Date().toISOString(),
    label: 'initial-setup'
  });
  saveAuthConfig();

  log.info('auth', 'Master password set for the first time.');

  res.cookie('master_token', rawToken, {
    httpOnly: true,
    sameSite: 'Strict',
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    path: '/'
  });

  res.json({ ok: true });
});

app.post('/api/master-login', async (req, res) => {
  if (!authConfig.passwordHash) {
    return res.status(400).json({ error: 'No password configured. Use setup.' });
  }

  const { password, remember } = req.body;
  if (!password) {
    return res.status(400).json({ error: 'Password required.' });
  }

  const valid = await verifyPassword(password, authConfig.passwordHash);
  if (!valid) {
    log.warn('auth', 'Master login failed: wrong password');
    return res.status(401).json({ error: 'Wrong password.' });
  }

  // Generate master token
  const rawToken = randomBytes(32).toString('hex');
  authConfig.masterTokens.push({
    tokenHash: hashMasterToken(rawToken),
    created: new Date().toISOString(),
    label: 'login'
  });

  // Prune old tokens (keep max 10)
  if (authConfig.masterTokens.length > 10) {
    authConfig.masterTokens = authConfig.masterTokens.slice(-10);
  }
  saveAuthConfig();

  const maxAge = remember
    ? 90 * 24 * 60 * 60 * 1000   // 90 days if "remember me"
    : 24 * 60 * 60 * 1000;        // 24 hours otherwise

  res.cookie('master_token', rawToken, {
    httpOnly: true,
    sameSite: 'Strict',
    maxAge,
    path: '/'
  });

  log.info('auth', `Master login successful (remember: ${!!remember})`);
  res.json({ ok: true });
});

app.post('/api/master-logout', (req, res) => {
  const masterToken = req.cookies?.master_token;
  if (masterToken) {
    const tokenH = hashMasterToken(masterToken);
    authConfig.masterTokens = authConfig.masterTokens.filter(t => t.tokenHash !== tokenH);
    saveAuthConfig();
  }
  res.clearCookie('master_token');
  res.clearCookie('token');
  res.clearCookie('group');
  log.info('auth', 'Master logout');
  res.json({ ok: true });
});

// ========== Welcome page ==========
app.get('/welcome', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'welcome.html'));
});

// Login page (master password)
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// ========== Groups API ==========
app.get('/api/groups', (req, res) => {
  const groups = groupsConfig.map(g => {
    const groupTerminals = getTerminalsForGroup(g.name);
    const activeToken = groupTokens.get(g.name);
    const hasActiveSession = activeToken ? true : false;

    // Count connected WS clients for this group
    let connectedClients = 0;
    for (const [id, info] of terminals) {
      if (info.group === g.name) {
        connectedClients += info.clients.size;
      }
    }

    return {
      name: g.name,
      icon: g.icon || '🖥',
      color: g.color || '#64ffda',
      maxTerminals: g.maxTerminals || 10,
      activeTerminals: groupTerminals.length,
      hasActiveSession,
      connectedClients
    };
  });
  res.json(groups);
});

// ========== Group CRUD API ==========

// Create a new group
app.post('/api/groups', (req, res) => {
  const { name, icon, color, maxTerminals } = req.body;
  if (!name || !name.trim()) {
    return res.status(400).json({ error: 'Group name is required' });
  }
  const trimmed = name.trim();
  if (groupsConfig.find(g => g.name.toLowerCase() === trimmed.toLowerCase())) {
    return res.status(409).json({ error: `Group "${trimmed}" already exists` });
  }
  const newGroup = {
    name: trimmed,
    icon: icon || '🖥',
    color: color || '#64ffda',
    maxTerminals: parseInt(maxTerminals) || 10
  };
  groupsConfig.push(newGroup);
  saveGroups();
  log.info('groups', `Created group "${trimmed}"`);
  res.json({ ok: true, group: newGroup });
});

// Update a group
app.put('/api/groups/:name', (req, res) => {
  const oldName = req.params.name;
  const idx = groupsConfig.findIndex(g => g.name === oldName);
  if (idx === -1) {
    return res.status(404).json({ error: `Group "${oldName}" not found` });
  }
  const { name, icon, color, maxTerminals } = req.body;
  const newName = (name && name.trim()) || oldName;

  // If renaming, check for duplicates
  if (newName !== oldName && groupsConfig.find(g => g.name.toLowerCase() === newName.toLowerCase())) {
    return res.status(409).json({ error: `Group "${newName}" already exists` });
  }

  // Update config
  groupsConfig[idx] = {
    name: newName,
    icon: icon !== undefined ? icon : groupsConfig[idx].icon,
    color: color !== undefined ? color : groupsConfig[idx].color,
    maxTerminals: maxTerminals !== undefined ? parseInt(maxTerminals) || 10 : groupsConfig[idx].maxTerminals
  };

  // If renamed, update terminal group tags and token map
  if (newName !== oldName) {
    for (const [id, info] of terminals) {
      if (info.group === oldName) info.group = newName;
    }
    const tokenInfo = groupTokens.get(oldName);
    if (tokenInfo) {
      groupTokens.delete(oldName);
      groupTokens.set(newName, tokenInfo);
    }
  }

  saveGroups();
  log.info('groups', `Updated group "${oldName}"${newName !== oldName ? ` → "${newName}"` : ''}`);
  res.json({ ok: true, group: groupsConfig[idx] });
});

// Delete a group
app.delete('/api/groups/:name', (req, res) => {
  const name = req.params.name;
  const idx = groupsConfig.findIndex(g => g.name === name);
  if (idx === -1) {
    return res.status(404).json({ error: `Group "${name}" not found` });
  }

  // Kill all terminals in the group
  const groupTerminalIds = [];
  for (const [id, info] of terminals) {
    if (info.group === name) {
      groupTerminalIds.push(id);
    }
  }
  for (const id of groupTerminalIds) {
    const info = terminals.get(id);
    if (info) {
      for (const ws of info.clients) {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'kicked', message: 'Group deleted.' }));
          ws.close();
        }
      }
      try { info.pty.kill(); } catch (_) {}
      terminals.delete(id);
    }
  }

  // Remove token
  groupTokens.delete(name);

  // Remove from config
  groupsConfig.splice(idx, 1);
  saveGroups();
  log.info('groups', `Deleted group "${name}" (killed ${groupTerminalIds.length} terminals)`);
  res.json({ ok: true, deleted: name, terminalsKilled: groupTerminalIds.length });
});

// ========== Login API (enter a group) ==========
app.post('/api/login', (req, res) => {
  const { group } = req.body;

  // Find group config
  const groupConfig = groupsConfig.find(g => g.name === group);
  if (!groupConfig) {
    return res.status(404).json({ error: 'Group not found' });
  }

  // Invalidate previous session for THIS group only
  const oldTokenInfo = groupTokens.get(group);
  const newToken = generateToken();
  groupTokens.set(group, { token: newToken, created: new Date().toISOString() });

  log.info('auth', `New login to group "${group}". Previous session for this group invalidated.`);

  // Kick only clients in this group
  if (oldTokenInfo) {
    kickGroupClients(group, 'Session expired: someone logged into this group from another device.');
  }

  // Set cookies
  res.cookie('token', newToken, {
    httpOnly: false,
    sameSite: 'Strict',
    maxAge: 24 * 60 * 60 * 1000,
    path: '/'
  });
  res.cookie('group', group, {
    httpOnly: false,
    sameSite: 'Strict',
    maxAge: 24 * 60 * 60 * 1000,
    path: '/'
  });

  res.json({ ok: true, group });
});

// Logout
app.post('/api/logout', (req, res) => {
  const token = req.cookies?.token;
  const group = getGroupForToken(token);
  if (group) {
    kickGroupClients(group, 'Logged out.');
    groupTokens.delete(group);
  }
  res.clearCookie('token');
  res.clearCookie('group');
  res.json({ ok: true });
});

// Apply auth to everything else
app.use(authMiddleware);

// ========== File System Browse API ==========

const fsPromises = fs.promises;

// Resolve and validate a directory path. Returns real path or null.
async function resolveDirectory(inputPath) {
  try {
    const resolved = path.resolve(inputPath);
    const real = await fsPromises.realpath(resolved);
    const stat = await fsPromises.stat(real);
    if (!stat.isDirectory()) return null;
    return real;
  } catch (_) {
    return null;
  }
}

/** Git Bash / MSYS bash paths on Windows (node-pty needs a real executable path). */
function getWindowsBashPath() {
  if (process.platform !== 'win32') return null;
  const roots = [
    process.env.ProgramFiles,
    process.env['ProgramFiles(x86)'],
    'C:\\Program Files',
    'C:\\Program Files (x86)'
  ].filter(Boolean);
  const seen = new Set();
  for (const root of roots) {
    const norm = path.normalize(root);
    if (seen.has(norm)) continue;
    seen.add(norm);
    const p = path.join(norm, 'Git', 'usr', 'bin', 'bash.exe');
    try {
      if (fs.existsSync(p)) return p;
    } catch (_) {}
  }
  return null;
}

// GET /api/platform — return server OS platform and available shells
app.get('/api/platform', (req, res) => {
  const plat = process.platform; // 'win32', 'darwin', 'linux', etc.
  let shells;
  let defaultShell = 'bash';
  if (plat === 'win32') {
    shells = [
      { id: 'bash', label: 'Bash', icon: '$' },
      { id: 'powershell', label: 'PowerShell', icon: 'PS' },
      { id: 'cmd', label: 'CMD', icon: '>' }
    ];
    defaultShell = getWindowsBashPath() ? 'bash' : 'powershell';
  } else if (plat === 'darwin') {
    shells = [
      { id: 'zsh', label: 'Zsh', icon: '$' },
      { id: 'bash', label: 'Bash', icon: '$' }
    ];
    defaultShell = shells[0].id;
  } else {
    shells = [
      { id: 'bash', label: 'Bash', icon: '$' },
      { id: 'zsh', label: 'Zsh', icon: '$' },
      { id: 'sh', label: 'sh', icon: '$' }
    ];
    defaultShell = shells[0].id;
  }
  res.json({ platform: plat, shells, defaultShell });
});

// GET /api/fs/drives — list available drive letters (Windows only)
app.get('/api/fs/drives', async (req, res) => {
  if (process.platform !== 'win32') {
    return res.json({ drives: [] });
  }
  const checks = [];
  for (let i = 'A'.charCodeAt(0); i <= 'Z'.charCodeAt(0); i++) {
    const drivePath = String.fromCharCode(i) + ':\\';
    checks.push(
      fsPromises.access(drivePath).then(() => drivePath, () => null)
    );
  }
  const results = await Promise.all(checks);
  res.json({ drives: results.filter(Boolean) });
});

// GET /api/fs/browse?path=<abs_path> — list directory contents
app.get('/api/fs/browse', async (req, res) => {
  const targetPath = req.query.path || process.env.HOME || process.env.USERPROFILE;

  const real = await resolveDirectory(targetPath);
  if (!real) {
    return res.status(400).json({ error: 'Path does not exist or is not a directory' });
  }

  try {
    const dirents = await fsPromises.readdir(real, { withFileTypes: true });
    const entries = [];

    for (const d of dirents) {
      const type = d.isDirectory() ? 'dir' : 'file';
      const entry = { name: d.name, type };
      if (type === 'file') {
        try {
          const st = await fsPromises.stat(path.join(real, d.name));
          entry.size = st.size;
        } catch (_) { entry.size = 0; }
        entry.extension = path.extname(d.name).toLowerCase();
      }
      entries.push(entry);
    }

    // Sort: dirs first, then alphabetical
    entries.sort((a, b) => {
      if (a.type !== b.type) return a.type === 'dir' ? -1 : 1;
      return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
    });

    const parent = path.dirname(real);
    res.json({
      path: real,
      separator: path.sep,
      parent: parent === real ? null : parent,
      entries
    });
  } catch (err) {
    if (err.code === 'EACCES' || err.code === 'EPERM') {
      return res.status(400).json({ error: 'Permission denied' });
    }
    return res.status(400).json({ error: err.message });
  }
});

// GET /api/fs/read?path=<abs_path> — read file contents for file viewer
app.get('/api/fs/read', async (req, res) => {
  const filePath = req.query.path;
  if (!filePath) {
    return res.status(400).json({ error: 'Path is required' });
  }

  try {
    const resolved = path.resolve(filePath);
    const real = await fsPromises.realpath(resolved);
    const stat = await fsPromises.stat(real);

    if (!stat.isFile()) {
      return res.status(404).json({ error: 'Not a file' });
    }

    const MAX_FILE_SIZE = 1048576; // 1 MB
    if (stat.size > MAX_FILE_SIZE) {
      return res.status(413).json({ error: `File too large (${(stat.size / 1024).toFixed(0)} KB, max 1 MB)` });
    }

    // Binary detection: check first 8KB for null bytes
    const buf = Buffer.alloc(Math.min(8192, stat.size));
    const fd = await fsPromises.open(real, 'r');
    await fd.read(buf, 0, buf.length, 0);
    await fd.close();
    if (buf.includes(0)) {
      return res.status(415).json({ error: 'Binary file cannot be displayed' });
    }

    const content = await fsPromises.readFile(real, 'utf-8');
    res.json({
      path: real,
      name: path.basename(real),
      content,
      size: stat.size,
      extension: path.extname(real).toLowerCase()
    });
  } catch (err) {
    if (err.code === 'ENOENT') {
      return res.status(404).json({ error: 'File not found' });
    }
    if (err.code === 'EACCES' || err.code === 'EPERM') {
      return res.status(403).json({ error: 'Permission denied' });
    }
    return res.status(500).json({ error: err.message });
  }
});

// ========== File Download API ==========
const MIME_MAP = {
  '.html': 'text/html', '.htm': 'text/html', '.css': 'text/css', '.js': 'application/javascript',
  '.json': 'application/json', '.xml': 'application/xml', '.txt': 'text/plain', '.md': 'text/markdown',
  '.csv': 'text/csv', '.pdf': 'application/pdf', '.zip': 'application/zip', '.gz': 'application/gzip',
  '.tar': 'application/x-tar', '.7z': 'application/x-7z-compressed', '.rar': 'application/vnd.rar',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif',
  '.webp': 'image/webp', '.bmp': 'image/bmp', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
  '.mp3': 'audio/mpeg', '.wav': 'audio/wav', '.mp4': 'video/mp4', '.webm': 'video/webm',
  '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf',
  '.doc': 'application/msword', '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xls': 'application/vnd.ms-excel', '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.ppt': 'application/vnd.ms-powerpoint', '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  '.exe': 'application/octet-stream', '.dll': 'application/octet-stream',
};

function getMimeType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  return MIME_MAP[ext] || 'application/octet-stream';
}

// GET /api/fs/download?path=<abs_path> — download a file
app.get('/api/fs/download', async (req, res) => {
  const filePath = req.query.path;
  if (!filePath) return res.status(400).json({ error: 'Path is required' });

  try {
    const resolved = path.resolve(filePath);
    const real = await fsPromises.realpath(resolved);
    const stat = await fsPromises.stat(real);

    if (!stat.isFile()) return res.status(404).json({ error: 'Not a file' });

    const MAX_DOWNLOAD = 100 * 1024 * 1024; // 100 MB
    if (stat.size > MAX_DOWNLOAD) {
      return res.status(413).json({ error: `File too large (${(stat.size / 1024 / 1024).toFixed(0)} MB, max 100 MB)` });
    }

    const fileName = path.basename(real);
    const mime = getMimeType(real);

    res.setHeader('Content-Type', mime);
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(fileName)}"`);
    res.setHeader('Content-Length', stat.size);

    const stream = fs.createReadStream(real);
    stream.pipe(res);
    stream.on('error', (err) => {
      log.error('fs', `Download stream error: ${err.message}`);
      if (!res.headersSent) res.status(500).json({ error: err.message });
    });

    log.info('fs', `Download: ${fileName} (${(stat.size / 1024).toFixed(1)} KB)`);
  } catch (err) {
    if (err.code === 'ENOENT') return res.status(404).json({ error: 'File not found' });
    if (err.code === 'EACCES' || err.code === 'EPERM') return res.status(403).json({ error: 'Permission denied' });
    return res.status(500).json({ error: err.message });
  }
});

// ========== Image Preview API ==========
const IMAGE_EXTENSIONS = ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.svg', '.ico'];

// GET /api/fs/preview?path=<abs_path> — serve image inline for preview
app.get('/api/fs/preview', async (req, res) => {
  const filePath = req.query.path;
  if (!filePath) return res.status(400).json({ error: 'Path is required' });

  try {
    const resolved = path.resolve(filePath);
    const real = await fsPromises.realpath(resolved);
    const stat = await fsPromises.stat(real);

    if (!stat.isFile()) return res.status(404).json({ error: 'Not a file' });

    const ext = path.extname(real).toLowerCase();
    if (!IMAGE_EXTENSIONS.includes(ext)) {
      return res.status(415).json({ error: `Not a supported image type: ${ext}` });
    }

    const MAX_PREVIEW = 50 * 1024 * 1024; // 50 MB
    if (stat.size > MAX_PREVIEW) {
      return res.status(413).json({ error: `Image too large (${(stat.size / 1024 / 1024).toFixed(0)} MB, max 50 MB)` });
    }

    const mime = getMimeType(real);
    const fileName = path.basename(real);

    res.setHeader('Content-Type', mime);
    res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(fileName)}"`);
    res.setHeader('Content-Length', stat.size);
    res.setHeader('Cache-Control', 'private, max-age=300'); // 5 min cache

    const stream = fs.createReadStream(real);
    stream.pipe(res);
    stream.on('error', (err) => {
      log.error('fs', `Preview stream error: ${err.message}`);
      if (!res.headersSent) res.status(500).json({ error: err.message });
    });
  } catch (err) {
    if (err.code === 'ENOENT') return res.status(404).json({ error: 'File not found' });
    if (err.code === 'EACCES' || err.code === 'EPERM') return res.status(403).json({ error: 'Permission denied' });
    return res.status(500).json({ error: err.message });
  }
});

// ========== File Upload to Directory API (File Manager) ==========
app.post('/api/fs/upload', (req, res) => {
  const contentType = req.headers['content-type'] || '';
  if (!contentType.startsWith('multipart/form-data')) {
    return res.status(400).json({ error: 'multipart/form-data required' });
  }

  const boundaryMatch = contentType.match(/boundary=(.+)/);
  if (!boundaryMatch) return res.status(400).json({ error: 'No boundary found' });
  const boundary = boundaryMatch[1].replace(/;.*$/, '').trim();

  const MAX_UPLOAD_SIZE = 100 * 1024 * 1024; // 100 MB
  let totalSize = 0;
  const chunks = [];
  let aborted = false;

  req.on('data', (chunk) => {
    totalSize += chunk.length;
    if (totalSize > MAX_UPLOAD_SIZE && !aborted) {
      aborted = true;
      res.status(413).json({ error: `Upload too large (max 100 MB)` });
      req.destroy();
      return;
    }
    chunks.push(chunk);
  });

  req.on('end', async () => {
    if (aborted) return;
    try {
      const body = Buffer.concat(chunks);
      const parts = parseMultipart(body, boundary);

      // Extract targetDir from form field
      let targetDir = null;
      for (const part of parts) {
        if (!part.filename && part.fieldName === 'targetDir') {
          targetDir = part.data.toString('utf-8').trim();
          break;
        }
      }

      if (!targetDir) {
        return res.status(400).json({ error: 'targetDir field is required' });
      }

      // Validate target directory exists
      let resolvedDir;
      try {
        const resolved = path.resolve(targetDir);
        resolvedDir = await fsPromises.realpath(resolved);
        const stat = await fsPromises.stat(resolvedDir);
        if (!stat.isDirectory()) {
          return res.status(400).json({ error: 'Target path is not a directory' });
        }
      } catch (err) {
        if (err.code === 'ENOENT') return res.status(400).json({ error: 'Target directory does not exist' });
        if (err.code === 'EACCES' || err.code === 'EPERM') return res.status(403).json({ error: 'Permission denied' });
        return res.status(400).json({ error: 'Invalid target directory: ' + err.message });
      }

      // Check directory is writable
      try {
        await fsPromises.access(resolvedDir, fs.constants.W_OK);
      } catch (_) {
        return res.status(403).json({ error: 'Target directory is not writable' });
      }

      // Save each file part with overwrite protection
      const saved = [];
      for (const part of parts) {
        if (!part.filename) continue; // skip text form fields

        // Sanitize filename: strip path separators and .. to prevent traversal
        const baseName = part.filename.replace(/[/\\]/g, '').replace(/\.\./g, '').trim();
        if (!baseName) continue;

        // Overwrite protection: append _1, _2, etc. if file exists
        let finalName = baseName;
        let filePath = path.join(resolvedDir, finalName);
        let counter = 1;
        while (fs.existsSync(filePath)) {
          const ext = path.extname(baseName);
          const stem = baseName.slice(0, baseName.length - ext.length);
          finalName = `${stem}_${counter}${ext}`;
          filePath = path.join(resolvedDir, finalName);
          counter++;
        }

        fs.writeFileSync(filePath, part.data);
        saved.push({
          name: part.filename,
          savedAs: finalName,
          size: part.data.length
        });
        log.info('fs', `Upload: ${finalName} to ${resolvedDir} (${(part.data.length / 1024).toFixed(1)} KB)`);
      }

      if (saved.length === 0) {
        return res.status(400).json({ error: 'No files found in upload' });
      }

      res.json({ ok: true, files: saved });
    } catch (err) {
      log.error('fs', `Upload failed: ${err.message}`);
      if (!res.headersSent) res.status(500).json({ error: err.message });
    }
  });
});

// ========== Create Folder API ==========
app.post('/api/fs/mkdir', express.json(), async (req, res) => {
  const { dirPath, name } = req.body || {};
  if (!dirPath || !name) {
    return res.status(400).json({ error: 'dirPath and name are required' });
  }

  // Sanitize folder name
  const sanitized = name.replace(/[/\\]/g, '').replace(/\.\./g, '').trim();
  if (!sanitized) {
    return res.status(400).json({ error: 'Invalid folder name' });
  }

  try {
    const resolved = path.resolve(dirPath);
    const real = await fsPromises.realpath(resolved);
    const stat = await fsPromises.stat(real);
    if (!stat.isDirectory()) {
      return res.status(400).json({ error: 'Parent path is not a directory' });
    }

    // Check writable
    await fsPromises.access(real, fs.constants.W_OK);

    const newPath = path.join(real, sanitized);
    await fsPromises.mkdir(newPath);
    log.info('fs', `Created folder: ${newPath}`);
    res.json({ ok: true, path: newPath });
  } catch (err) {
    if (err.code === 'EEXIST') return res.status(409).json({ error: 'Folder already exists' });
    if (err.code === 'ENOENT') return res.status(404).json({ error: 'Parent directory not found' });
    if (err.code === 'EACCES' || err.code === 'EPERM') return res.status(403).json({ error: 'Permission denied' });
    return res.status(500).json({ error: err.message });
  }
});

// ========== Delete File/Folder API ==========
app.delete('/api/fs/delete', express.json(), async (req, res) => {
  const { path: filePath } = req.body || {};
  if (!filePath) {
    return res.status(400).json({ error: 'path is required' });
  }

  try {
    const resolved = path.resolve(filePath);
    const real = await fsPromises.realpath(resolved);
    const stat = await fsPromises.stat(real);

    // Check parent is writable
    const parentDir = path.dirname(real);
    await fsPromises.access(parentDir, fs.constants.W_OK);

    if (stat.isDirectory()) {
      await fsPromises.rmdir(real); // empty dirs only
      log.info('fs', `Deleted folder: ${real}`);
    } else {
      await fsPromises.unlink(real);
      log.info('fs', `Deleted file: ${real}`);
    }

    res.json({ ok: true });
  } catch (err) {
    if (err.code === 'ENOTEMPTY') return res.status(400).json({ error: 'Directory is not empty' });
    if (err.code === 'ENOENT') return res.status(404).json({ error: 'File or folder not found' });
    if (err.code === 'EACCES' || err.code === 'EPERM') return res.status(403).json({ error: 'Permission denied' });
    if (err.code === 'EBUSY') return res.status(400).json({ error: 'File is in use' });
    return res.status(500).json({ error: err.message });
  }
});

// ========== Image Upload API (for Claude Code attach) ==========
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// Accept raw binary via multipart — we parse manually to avoid deps
app.post('/api/upload-images', (req, res) => {
  const contentType = req.headers['content-type'] || '';
  if (!contentType.startsWith('multipart/form-data')) {
    return res.status(400).json({ error: 'multipart/form-data required' });
  }

  const boundary = contentType.split('boundary=')[1];
  if (!boundary) return res.status(400).json({ error: 'No boundary' });

  const chunks = [];
  req.on('data', (chunk) => chunks.push(chunk));
  req.on('end', () => {
    try {
      const body = Buffer.concat(chunks);
      const parts = parseMultipart(body, boundary);
      const saved = [];

      for (const part of parts) {
        if (!part.filename) continue;

        // Sanitize filename, keep extension
        const ext = path.extname(part.filename).toLowerCase() || '.png';
        const allowed = ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.svg'];
        if (!allowed.includes(ext)) continue;

        const ts = Date.now();
        const rand = crypto.randomBytes(4).toString('hex');
        const safeName = `img_${ts}_${rand}${ext}`;
        const filePath = path.join(UPLOAD_DIR, safeName);

        fs.writeFileSync(filePath, part.data);
        saved.push({ name: safeName, path: filePath, size: part.data.length });
        log.info('upload', `Saved image: ${safeName} (${(part.data.length / 1024).toFixed(1)} KB)`);
      }

      if (saved.length === 0) {
        return res.status(400).json({ error: 'No valid image files found' });
      }

      res.json({ ok: true, files: saved });
    } catch (err) {
      log.error('upload', `Image upload failed: ${err.message}`, { stack: err.stack });
      res.status(500).json({ error: err.message });
    }
  });
});

// ========== General File Upload API (any file type, for attaching to terminal input) ==========
app.post('/api/upload-files', (req, res) => {
  const contentType = req.headers['content-type'] || '';
  if (!contentType.startsWith('multipart/form-data')) {
    return res.status(400).json({ error: 'multipart/form-data required' });
  }

  const boundary = contentType.split('boundary=')[1];
  if (!boundary) return res.status(400).json({ error: 'No boundary' });

  const MAX_SIZE = 100 * 1024 * 1024; // 100MB total
  let totalSize = 0;
  const chunks = [];

  req.on('data', (chunk) => {
    totalSize += chunk.length;
    if (totalSize > MAX_SIZE) {
      req.destroy();
      return res.status(413).json({ error: 'Upload too large (max 100MB)' });
    }
    chunks.push(chunk);
  });

  req.on('end', () => {
    try {
      const body = Buffer.concat(chunks);
      const parts = parseMultipart(body, boundary);
      const saved = [];

      for (const part of parts) {
        if (!part.filename) continue;

        // Sanitize filename: keep original name but remove path separators and dangerous chars
        const origName = part.filename.replace(/[/\\:*?"<>|]/g, '_').replace(/\s+/g, '_');
        const ext = path.extname(origName);
        const base = path.basename(origName, ext) || 'file';
        const ts = Date.now();
        const rand = crypto.randomBytes(3).toString('hex');
        const safeName = `${base}_${ts}_${rand}${ext}`;
        const filePath = path.join(UPLOAD_DIR, safeName);

        fs.writeFileSync(filePath, part.data);
        saved.push({ name: origName, path: filePath, size: part.data.length });
        log.info('upload', `Saved file: ${safeName} (${(part.data.length / 1024).toFixed(1)} KB)`);
      }

      if (saved.length === 0) {
        return res.status(400).json({ error: 'No files found in upload' });
      }

      res.json({ ok: true, files: saved });
    } catch (err) {
      log.error('upload', `File upload failed: ${err.message}`, { stack: err.stack });
      res.status(500).json({ error: err.message });
    }
  });
});

// Simple multipart parser (no deps)
function parseMultipart(body, boundary) {
  const sep = Buffer.from(`--${boundary}`);
  const parts = [];
  let start = 0;

  while (true) {
    const idx = body.indexOf(sep, start);
    if (idx === -1) break;

    if (start > 0) {
      // Extract part between previous boundary and this one
      // Skip \r\n after boundary, and \r\n before next boundary
      let partStart = start;
      let partEnd = idx - 2; // remove trailing \r\n
      if (partEnd > partStart) {
        const partBuf = body.slice(partStart, partEnd);
        const headerEnd = partBuf.indexOf('\r\n\r\n');
        if (headerEnd !== -1) {
          const headerStr = partBuf.slice(0, headerEnd).toString('utf-8');
          const data = partBuf.slice(headerEnd + 4);

          // Parse headers
          const filenameMatch = headerStr.match(/filename="([^"]+)"/);
          const filename = filenameMatch ? filenameMatch[1] : null;
          const nameMatch = headerStr.match(/name="([^"]+)"/);
          const fieldName = nameMatch ? nameMatch[1] : null;

          parts.push({ headers: headerStr, filename, fieldName, data });
        }
      }
    }

    start = idx + sep.length;
    // Skip \r\n after boundary
    if (body[start] === 0x0d && body[start + 1] === 0x0a) start += 2;
    // Check for -- (end marker)
    if (body[start] === 0x2d && body[start + 1] === 0x2d) break;
  }

  return parts;
}

// ========== Text Upload API (for long text paste) ==========
app.post('/api/upload-text', express.text({ limit: '5mb', type: '*/*' }), (req, res) => {
  try {
    const text = typeof req.body === 'string' ? req.body : String(req.body);
    if (!text || text.length === 0) {
      return res.status(400).json({ error: 'No text provided' });
    }

    const MAX_TEXT_SIZE = 5 * 1024 * 1024; // 5 MB
    if (Buffer.byteLength(text, 'utf-8') > MAX_TEXT_SIZE) {
      return res.status(413).json({ error: 'Text too large (max 5 MB)' });
    }

    const ts = Date.now();
    const rand = crypto.randomBytes(4).toString('hex');
    const safeName = `text_${ts}_${rand}.txt`;
    const filePath = path.join(UPLOAD_DIR, safeName);

    fs.writeFileSync(filePath, text, 'utf-8');
    log.info('upload', `Saved text file: ${safeName} (${(Buffer.byteLength(text, 'utf-8') / 1024).toFixed(1)} KB, ${text.length} chars)`);

    res.json({ ok: true, name: safeName, path: filePath, size: Buffer.byteLength(text, 'utf-8'), chars: text.length });
  } catch (err) {
    log.error('upload', `Text upload failed: ${err.message}`, { stack: err.stack });
    res.status(500).json({ error: err.message });
  }
});

// Cleanup old uploads (older than 24h) periodically
setInterval(() => {
  try {
    const now = Date.now();
    const files = fs.readdirSync(UPLOAD_DIR);
    for (const f of files) {
      const fp = path.join(UPLOAD_DIR, f);
      const stat = fs.statSync(fp);
      if (now - stat.mtimeMs > 24 * 60 * 60 * 1000) {
        fs.unlinkSync(fp);
        log.info('upload', `Cleaned up old upload: ${f}`);
      }
    }
  } catch (_) {}
}, 60 * 60 * 1000); // every hour

// Serve static files (after auth)
app.use(express.static(path.join(__dirname, 'public')));

// ========== Terminal state (persistent, per-group) ==========
const terminals = new Map(); // id -> { pty, shell, created, clients, getBuffer, shellLabel, group }
let nextId = 1;

function getTerminalsForGroup(groupName) {
  const list = [];
  for (const [id, info] of terminals) {
    if (info.group === groupName) {
      list.push({ id, shell: info.shellLabel, created: info.created, pid: info.pty.pid });
    }
  }
  return list;
}

app.get('/api/terminals', (req, res) => {
  // Only return terminals for the authenticated group
  const list = getTerminalsForGroup(req.group);
  res.json(list);
});

app.get('/api/group-info', (req, res) => {
  const groupConfig = groupsConfig.find(g => g.name === req.group);
  res.json({
    name: req.group,
    icon: groupConfig?.icon || '🖥',
    color: groupConfig?.color || '#64ffda',
    maxTerminals: groupConfig?.maxTerminals || 10,
    activeTerminals: getTerminalsForGroup(req.group).length
  });
});

app.post('/api/terminal/new', async (req, res) => {
  const shell = req.body.shell
    || (process.platform === 'win32'
      ? (getWindowsBashPath() ? 'bash' : 'powershell')
      : 'bash');
  const cols = parseInt(req.body.cols) || 120;
  const rows = parseInt(req.body.rows) || 40;
  const group = req.group;
  const requestedCwd = req.body.cwd || '';

  // Check max terminals for group
  const groupConfig = groupsConfig.find(g => g.name === group);
  const maxTerminals = groupConfig?.maxTerminals || 10;
  const currentCount = getTerminalsForGroup(group).length;
  if (currentCount >= maxTerminals) {
    return res.status(400).json({ error: `Group "${group}" has reached max terminals (${maxTerminals})` });
  }

  const id = nextId++;

  // Validate and resolve cwd
  const homePath = process.env.HOME || process.env.USERPROFILE;
  let cwd = homePath;
  if (requestedCwd) {
    const resolved = await resolveDirectory(requestedCwd);
    if (resolved) cwd = resolved;
  }

  // Resolve shell command based on platform
  let shellCmd, shellLabel;
  const isWin = process.platform === 'win32';

  if (isWin) {
    // Windows: node-pty needs full paths
    if (shell === 'bash' || shell === 'bash.exe') {
      shellCmd = getWindowsBashPath();
      shellLabel = 'bash';
      if (!shellCmd) {
        return res.status(400).json({
          error: 'Git Bash not found. Install Git for Windows, or use PowerShell / CMD.'
        });
      }
    } else if (shell === 'powershell.exe' || shell === 'powershell') {
      shellCmd = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
      shellLabel = 'powershell';
    } else if (shell === 'cmd.exe' || shell === 'cmd') {
      shellCmd = 'C:\\Windows\\System32\\cmd.exe';
      shellLabel = 'cmd';
    } else {
      // Legacy default / unknown id: prefer PowerShell on Windows
      shellCmd = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
      shellLabel = 'powershell';
    }
  } else {
    // macOS / Linux: use standard shell paths
    if (shell === 'zsh') {
      shellCmd = '/bin/zsh';
      shellLabel = 'zsh';
    } else if (shell === 'sh') {
      shellCmd = '/bin/sh';
      shellLabel = 'sh';
    } else {
      shellCmd = '/bin/bash';
      shellLabel = 'bash';
    }
  }

  log.info('pty', `Creating terminal ${id} for group "${group}": ${shellCmd} (${cols}x${rows}) cwd=${cwd}`);

  try {
    const MAX_BUFFER = 100000;
    const ptyProc = pty.spawn(shellCmd, [], {
      name: 'xterm-256color',
      cols, rows,
      cwd,
      env: process.env
    });

    const termInfo = {
      pty: ptyProc,
      shell: shellCmd,
      shellLabel,
      _outputBuffer: '',
      created: new Date().toISOString(),
      clients: new Set(),
      getBuffer() { return this._outputBuffer; },
      group
    };

    ptyProc.onData((data) => {
      termInfo._outputBuffer += data;
      if (termInfo._outputBuffer.length > MAX_BUFFER) {
        termInfo._outputBuffer = termInfo._outputBuffer.slice(-MAX_BUFFER);
      }
      if (termInfo.clients) {
        const msg = JSON.stringify({ type: 'output', data });
        for (const ws of termInfo.clients) {
          try {
            if (ws.readyState === WebSocket.OPEN) ws.send(msg);
          } catch (_) { termInfo.clients.delete(ws); }
        }
      }
    });

    ptyProc.onExit(({ exitCode }) => {
      log.info('pty', `Terminal ${id} exited (code ${exitCode})`);
      cleanupTerminal(id);
    });

    terminals.set(id, termInfo);

    res.json({ id, shell: shellLabel, cols, rows, group, cwd });
  } catch (err) {
    log.error('pty', `Failed to create terminal: ${err.message}`, { stack: err.stack });
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/terminal/:id/resize', async (req, res) => {
  const id = parseInt(req.params.id);
  const info = terminals.get(id);
  if (!info) return res.status(404).json({ error: 'Terminal not found' });
  if (info.group !== req.group) return res.status(403).json({ error: 'Not your terminal' });

  const cols = parseInt(req.body.cols) || 120;
  const rows = parseInt(req.body.rows) || 40;
  info.pty.resize(cols, rows);
  res.json({ ok: true, cols, rows });
});

app.delete('/api/terminal/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  const info = terminals.get(id);
  if (!info) return res.status(404).json({ error: 'Terminal not found' });
  if (info.group !== req.group) return res.status(403).json({ error: 'Not your terminal' });

  try {
    try { info.pty.kill(); } catch (_) {}
    terminals.delete(id);
    res.json({ ok: true, id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

function cleanupTerminal(id) {
  const info = terminals.get(id);
  if (info) {
    for (const ws of info.clients) {
      try {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'exit', code: 0 }));
          ws.close();
        }
      } catch (_) {}
    }
  }
  terminals.delete(id);
}

// ========== Server + WebSocket ==========

const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true, maxPayload: 5 * 1024 * 1024 });

// WebSocket upgrade — validate master token + group token + group isolation
server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  // Validate master auth first (parse cookies from raw header)
  if (authConfig.passwordHash) {
    const cookieHeader = req.headers.cookie || '';
    const cookies = {};
    cookieHeader.split(';').forEach(c => {
      const [key, ...val] = c.trim().split('=');
      if (key) cookies[key.trim()] = val.join('=').trim();
    });
    if (!isValidMasterToken(cookies.master_token)) {
      log.warn('ws', 'Rejected: invalid master token');
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }
  }

  const token = url.searchParams.get('token');
  const group = getGroupForToken(token);
  if (!group) {
    log.warn('ws', 'Rejected: invalid group token');
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy();
    return;
  }

  if (url.pathname !== '/ws') {
    socket.destroy();
    return;
  }

  wss.handleUpgrade(req, socket, head, (ws) => {
    ws._authToken = token;
    ws._group = group;
    wss.emit('connection', ws, req);
  });
});

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const id = parseInt(url.searchParams.get('id'));

  const info = terminals.get(id);
  if (!info) {
    ws.send(JSON.stringify({ type: 'error', message: 'Terminal not found' }));
    ws.close();
    return;
  }

  // Group isolation: can only connect to terminals in your group
  if (info.group !== ws._group) {
    ws.send(JSON.stringify({ type: 'error', message: 'Not your terminal' }));
    ws.close();
    return;
  }

  log.info('ws', `Client connected to terminal ${id} (group: ${ws._group})`);
  info.clients.add(ws);

  // Send buffered output
  const buffer = info.getBuffer();
  if (buffer) {
    ws.send(JSON.stringify({ type: 'output', data: buffer }));
  }

  ws.on('message', (msg) => {
    // Re-validate token on each message
    if (getGroupForToken(ws._authToken) !== ws._group) {
      ws.send(JSON.stringify({ type: 'kicked', message: 'Session expired.' }));
      ws.close();
      return;
    }

    try {
      const parsed = JSON.parse(msg);
      switch (parsed.type) {
        case 'input':
          info.pty.write(parsed.data);
          break;
        case 'resize':
          info.pty.resize(parsed.cols, parsed.rows);
          break;
      }
    } catch (err) {
      info.pty.write(msg.toString());
    }
  });

  ws.on('error', (err) => {
    log.warn('ws', `Client error on terminal ${id}: ${err.message}`);
    info.clients.delete(ws);
  });

  ws.on('close', () => {
    log.info('ws', `Client disconnected from terminal ${id}`);
    info.clients.delete(ws);
  });
});

// Kick only clients in a specific group
function kickGroupClients(groupName, reason) {
  for (const [id, info] of terminals) {
    if (info.group !== groupName) continue;
    for (const ws of info.clients) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'kicked', message: reason }));
        ws.close();
      }
    }
    info.clients.clear();
  }
}

server.listen(PORT, () => {
  log.info('server', `========================================`);
  log.info('server', `Web Terminal Hub running on port ${PORT}`);
  log.info('server', `Groups: ${groupsConfig.map(g => g.name).join(', ')}`);
  log.info('server', `Master password: ${authConfig.passwordHash ? 'ENABLED' : 'NOT SET (visit /login to set up)'}`);
  log.info('server', `Log file: ${path.join(LOG_DIR, getLogFileName())}`);
  log.info('server', `http://localhost:${PORT}`);
  log.info('server', `========================================`);
});

process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);

function cleanup() {
  log.info('server', 'Shutting down...');
  for (const [id, info] of terminals) {
    try { info.pty.kill(); } catch (_) {}
  }
  terminals.clear();
  process.exit(0);
}
