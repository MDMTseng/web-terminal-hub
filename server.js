const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const pty = require('node-pty');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const PORT = process.env.HUB_PORT || 9091;

// ========== Groups config ==========
let groupsConfig = [];
try {
  const raw = fs.readFileSync(path.join(__dirname, 'groups.json'), 'utf-8');
  groupsConfig = JSON.parse(raw).groups || [];
  console.log(`[groups] Loaded ${groupsConfig.length} groups: ${groupsConfig.map(g => g.name).join(', ')}`);
} catch (err) {
  console.error('[groups] Failed to load groups.json, using defaults:', err.message);
  groupsConfig = [
    { name: 'Dev', icon: '🛠', color: '#64ffda', maxTerminals: 10 },
    { name: 'Ops', icon: '🖥', color: '#f78c6c', maxTerminals: 10 }
  ];
}

const GROUPS_FILE = path.join(__dirname, 'groups.json');

function saveGroups() {
  fs.writeFileSync(GROUPS_FILE, JSON.stringify({ groups: groupsConfig }, null, 2), 'utf-8');
  console.log(`[groups] Saved ${groupsConfig.length} groups to groups.json`);
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

// ========== Welcome page (replaces login) ==========
app.get('/welcome', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'welcome.html'));
});

// Redirect old /login to /welcome
app.get('/login', (req, res) => {
  res.redirect('/welcome');
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
  console.log(`[groups] Created group "${trimmed}"`);
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
  console.log(`[groups] Updated group "${oldName}"${newName !== oldName ? ` → "${newName}"` : ''}`);
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
  console.log(`[groups] Deleted group "${name}" (killed ${groupTerminalIds.length} terminals)`);
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

  console.log(`[auth] New login to group "${group}". Previous session for this group invalidated.`);

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

  console.log(`[pty] Creating terminal ${id} for group "${group}": ${shellCmd} (${cols}x${rows}) cwd=${cwd}`);

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
      console.log(`[pty:${id}] Exited with code ${exitCode}`);
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
    console.error(`[pty] Failed to create terminal:`, err);
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

// WebSocket upgrade — validate token + group isolation
server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  const token = url.searchParams.get('token');
  const group = getGroupForToken(token);
  if (!group) {
    console.log(`[ws] Rejected: invalid token`);
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

  console.log(`[ws] Client connected to terminal ${id} (group: ${ws._group})`);
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
    console.log(`[ws] Client disconnected from terminal ${id}`);
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
  console.log(`\n========================================`);
  console.log(`  Web Terminal Hub running on port ${PORT}`);
  console.log(`  Groups: ${groupsConfig.map(g => g.name).join(', ')}`);
  console.log(`  No password - click to enter any group`);
  console.log(`  http://localhost:${PORT}`);
  console.log(`========================================\n`);
});

process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);

function cleanup() {
  console.log('\n[hub] Shutting down...');
  for (const [id, info] of terminals) {
    try { info.pty.kill(); } catch (_) {}
  }
  terminals.clear();
  process.exit(0);
}
