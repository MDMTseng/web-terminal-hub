# Web Terminal Hub

A self-hosted, browser-based terminal multiplexer with multi-tab support, workspace isolation, file management, and mobile-optimized virtual keyboard.

Access full shell sessions (Bash, PowerShell, CMD) from any browser — desktop or mobile — with master password protection, group-based workspaces, and optional remote tunneling via ngrok or Cloudflare.

---

## Features

### Terminal
- **Multi-tab sessions** with independent shell instances per workspace
- **Shell support**: Bash, PowerShell, cmd.exe
- **GPU-accelerated rendering** via xterm.js (WebGL > Canvas > DOM fallback)
- **Touch scroll with inertia** for smooth mobile scrolling
- **Pinch-to-zoom** font size adjustment
- **Output buffering** (100KB per terminal) for seamless reconnection
- **Auto-reconnect** with per-terminal overlay and countdown

### File Management
- **Browse** directories with breadcrumb navigation
- **Upload** files with drag-and-drop (overwrite protection)
- **Download** and **preview** files (text, images up to 50MB)
- **Create/delete** folders and files
- **Favorites** and **recent directories** for quick access
- **Windows drive picker** for navigating across volumes

### Mobile UX
- **Virtual keyboard** with compact bar (arrows, Tab, Esc, ^C) and expandable drawer
- **Claude Code mode**: Shortcuts for Model, Think, Verbose, BgTask, Rewind, @File, /Cmd
- **Shell mode**: Modifier toggles (Ctrl/Alt/Shift), signals (^D, ^Z), symbols, pipes
- **Links panel**: Auto-captures URLs and file paths from terminal output
- **Text input modal**: Voice dictation, image/file attachment, paste-as-file
- **Haptic feedback** on key actions
- **Toast notifications** for transient feedback

### Security
- **Two-tier authentication**: Master password (scrypt) + per-group session tokens
- **Latest-login-wins**: New login to a group invalidates previous sessions
- **WebSocket validation**: Token checked on every message
- **Group isolation**: Users only access terminals in their authenticated workspace
- **No hardcoded secrets**: All auth data in gitignored `auth.json`

### Deployment
- **Reverse proxy ready**: `BASE_PATH` support for path-based routing
- **Optional tunneling**: ngrok or Cloudflare tunnel for remote access
- **Windows service**: Install as Scheduled Task with auto-restart
- **Background scripts**: PowerShell and Bash launchers included

---

## Quick Start

### Prerequisites

- **Node.js** v16+
- **npm**
- **Git for Windows** (provides Bash shell) — optional

### Install & Run

```bash
git clone https://github.com/MDMTseng/web-terminal-hub.git
cd web-terminal-hub
npm install
npm start
```

Open **http://localhost:9091** in your browser.

On first visit you'll be prompted to set a **master password**, then create or select a workspace group to start using terminals.

### Background Mode (Windows)

```powershell
# Start server (+ optional ngrok tunnel)
powershell -File start_bg.ps1
powershell -File start_bg.ps1 -tunnel

# Stop everything
powershell -File stop.ps1
```

### Install as Windows Service

```powershell
# Install auto-start on login
powershell -ExecutionPolicy Bypass -File install_service.ps1

# With tunnel
powershell -ExecutionPolicy Bypass -File install_service.ps1 -WithTunnel

# Uninstall
powershell -ExecutionPolicy Bypass -File install_service.ps1 -Uninstall
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HUB_PORT` | `9091` | Server listen port |
| `BASE_PATH` | *(empty)* | URL prefix for reverse proxy (e.g. `/webterm`) |
| `PROXY_STRIPS_BASE_PATH` | `false` | Set `true` if your proxy strips the prefix before forwarding |

### hub.local.json (optional, gitignored)

```json
{
  "basePath": "/webterm",
  "proxyStripsBasePath": true
}
```

### groups.json (auto-created)

Workspace definitions — editable via the UI or directly:

```json
{
  "groups": [
    { "name": "Dev", "icon": "🛠", "color": "#64ffda", "maxTerminals": 10 },
    { "name": "Ops", "icon": "🖥", "color": "#f78c6c", "maxTerminals": 10 }
  ]
}
```

---

## Authentication Flow

```
Browser                          Server
  │                                │
  ├── GET /login ─────────────────►│  (first visit: set master password)
  ├── POST /api/master-login ─────►│  → master_token cookie (24h or 90d)
  │                                │
  ├── GET /welcome ───────────────►│  (select workspace group)
  ├── POST /api/login {group} ────►│  → group token cookie (24h)
  │                                │
  ├── WebSocket /ws?token=&id= ───►│  (validates master + group tokens)
  │◄──── terminal I/O ────────────►│
```

- **Master password**: Hashed with scrypt (N=16384, r=8, p=1), timing-safe comparison
- **Tokens**: Cryptographic random 256-bit, stored as SHA-256 hashes
- **Group isolation**: Each group has one active token; new login kicks previous session

---

## Project Structure

```
web-terminal-hub/
├── server.js              # Express + WebSocket + PTY server
├── package.json
├── groups.json            # Workspace definitions
├── public/
│   ├── index.html         # Main terminal UI (xterm.js)
│   ├── welcome.html       # Group selection page
│   ├── login.html         # Master password setup/login
│   └── style.css          # Dark theme design system (~300 CSS variables)
├── start_bg.ps1           # Windows: start server in background
├── stop.ps1               # Windows: stop server + tunnel
├── install_service.ps1    # Windows: install as Scheduled Task
├── run_tunnel.ps1         # Tunnel wrapper (ngrok)
├── start-ngrok.ps1        # ngrok with retry logic
├── start.sh               # Bash: start server + Cloudflare tunnel
├── logs/                  # Daily timestamped logs (gitignored)
├── uploads/               # Temp files, auto-cleaned after 24h (gitignored)
└── auth.json              # Master password hash + tokens (gitignored)
```

---

## API Reference

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/master-status` | Check if master password is set |
| `POST` | `/api/master-setup` | Set master password (first-time only) |
| `POST` | `/api/master-login` | Login with master password |
| `POST` | `/api/master-logout` | Logout, clear all tokens |
| `POST` | `/api/login` | Enter a workspace group |
| `POST` | `/api/logout` | Leave current group |

### Terminals

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/terminals` | List terminals in current group |
| `POST` | `/api/terminal/new` | Create terminal `{shell, cols, rows, cwd}` |
| `POST` | `/api/terminal/:id/resize` | Resize terminal `{cols, rows}` |
| `DELETE` | `/api/terminal/:id` | Kill terminal |
| `WebSocket` | `/ws?token=&id=` | Terminal I/O stream |

### File System

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/fs/browse?path=` | List directory contents |
| `GET` | `/api/fs/drives` | List Windows drive letters |
| `GET` | `/api/fs/read?path=` | Read text file (max 1MB) |
| `GET` | `/api/fs/download?path=` | Download file (max 100MB) |
| `GET` | `/api/fs/preview?path=` | Preview image (max 50MB) |
| `POST` | `/api/fs/upload` | Upload files to directory |
| `POST` | `/api/fs/mkdir` | Create folder `{dirPath, name}` |
| `DELETE` | `/api/fs/delete` | Delete file or empty folder |

### Groups

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/groups` | List all groups with stats |
| `POST` | `/api/groups` | Create group |
| `PUT` | `/api/groups/:name` | Update group |
| `DELETE` | `/api/groups/:name` | Delete group (kills all terminals) |

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| **Runtime** | Node.js |
| **Server** | Express 4.x |
| **Terminal** | node-pty (pseudo-terminal) |
| **WebSocket** | ws |
| **Frontend** | Vanilla JS + xterm.js 5.3 |
| **Rendering** | WebGL / Canvas / DOM (auto-fallback) |
| **Auth** | crypto.scrypt + SHA-256 (no external deps) |
| **Styling** | Custom CSS dark theme (no framework) |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Server won't start | Check if port 9091 is in use: `netstat -ano \| findstr :9091` |
| WebSocket errors | Ensure both master and group tokens are valid (re-login) |
| Terminal not responding | Check browser console for "kicked" messages; refresh page |
| Password lost | Delete `auth.json` and restart — set a new password at `/login` |
| Upload fails | Check disk space and directory permissions |

---

## License

MIT
