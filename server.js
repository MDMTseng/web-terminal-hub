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

function getLogFileName() {
  const d = new Date();
  return `hub-${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}.log`;
}

function timestamp() {
  return new Date().toISOString();
}

function writeLog(level, category, message, extra) {
  const ts = timestamp();
  const line = extra
    ? `[${ts}] [${level}] [${category}] ${message} | ${JSON.stringify(extra)}`
    : `[${ts}] [${level}] [${category}] ${message}`;

  // Console output
  if (level === 'ERROR' || level === 'FATAL') {
    process.stderr.write(line + '\n');
  } else {
    process.stdout.write(line + '\n');
  }

  // File output
  try {
    fs.appendFileSync(path.join(LOG_DIR, getLogFileName()), line + '\n');
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
  log.fatal('process', `Uncaught Exception: ${err.message}`, { stack: err.stack });
  // Keep running — don't crash on recoverable errors
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

app.use(express.json());

// ========== Request Logging Middleware ==========
app.use((req, res, next) => {
  const start = Date.now();
  const originalEnd = res.end;
  res.end = function(...args) {
    const duration = Date.now() - start;
    const status = res.statusCode;
    // Only log API requests and errors (skip static assets to reduce noise)
    if (req.path.startsWith('/api/') || status >= 400) {
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

// GET /api/fs/drives — list available drive letters (Windows)
app.get('/api/fs/drives', async (req, res) => {
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
      entries.push({ name: d.name, type });
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
  const shell = req.body.shell || 'bash';
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

  // node-pty on Windows needs full paths
  let shellCmd, shellLabel;
  if (shell === 'powershell.exe' || shell === 'powershell') {
    shellCmd = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
    shellLabel = 'powershell';
  } else if (shell === 'cmd.exe' || shell === 'cmd') {
    shellCmd = 'C:\\Windows\\System32\\cmd.exe';
    shellLabel = 'cmd';
  } else {
    shellCmd = 'C:\\Program Files\\Git\\usr\\bin\\bash.exe';
    shellLabel = 'bash';
  }

  log.info('pty', `Creating terminal ${id} for group "${group}": ${shellCmd} (${cols}x${rows}) cwd=${cwd}`);

  try {
    const ptyProc = pty.spawn(shellCmd, [], {
      name: 'xterm-256color',
      cols,
      rows,
      cwd,
      env: process.env
    });

    let outputBuffer = '';
    const MAX_BUFFER = 100000; // 100KB buffer for reconnection

    ptyProc.onData((data) => {
      outputBuffer += data;
      if (outputBuffer.length > MAX_BUFFER) {
        outputBuffer = outputBuffer.slice(-MAX_BUFFER);
      }
      const info = terminals.get(id);
      if (info && info.clients) {
        for (const ws of info.clients) {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'output', data }));
          }
        }
      }
    });

    ptyProc.onExit(({ exitCode }) => {
      log.info('pty', `Terminal ${id} exited with code ${exitCode}`);
      const info = terminals.get(id);
      if (info) {
        for (const ws of info.clients) {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'exit', code: exitCode }));
            ws.close();
          }
        }
      }
      terminals.delete(id);
    });

    terminals.set(id, {
      pty: ptyProc,
      shell: shellCmd,
      shellLabel,
      created: new Date().toISOString(),
      clients: new Set(),
      getBuffer: () => outputBuffer,
      group // tag terminal with its group
    });

    res.json({ id, shell: shellLabel, cols, rows, group, cwd });
  } catch (err) {
    log.error('pty', `Failed to create terminal: ${err.message}`, { stack: err.stack });
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/terminal/:id/resize', (req, res) => {
  const id = parseInt(req.params.id);
  const info = terminals.get(id);
  if (!info) return res.status(404).json({ error: 'Terminal not found' });
  if (info.group !== req.group) return res.status(403).json({ error: 'Not your terminal' });

  const cols = parseInt(req.body.cols) || 120;
  const rows = parseInt(req.body.rows) || 40;
  info.pty.resize(cols, rows);
  res.json({ ok: true, cols, rows });
});

app.delete('/api/terminal/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const info = terminals.get(id);
  if (!info) return res.status(404).json({ error: 'Terminal not found' });
  if (info.group !== req.group) return res.status(403).json({ error: 'Not your terminal' });

  try {
    info.pty.kill();
    terminals.delete(id);
    res.json({ ok: true, id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== Server + WebSocket ==========

const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });

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
