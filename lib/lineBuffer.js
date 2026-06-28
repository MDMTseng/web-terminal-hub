'use strict';

// ANSI-aware, byte-bounded scrollback line buffer.
// Splits PTY output into lines on \n ONLY when outside an ANSI escape sequence, so escape
// codes are never cut mid-sequence. Stores the RAW bytes verbatim (no \r collapsing) —
// cursor-addressed output must be replayed exactly.
//
// Alternate-screen awareness: full-screen TUIs (tmux, vim, htop, …) switch to the alternate
// screen (CSI ?1049h / ?1047h / ?47h) and repaint the whole viewport via cursor positioning.
// That output is NOT linear scrollback — caching it is pointless (it never scrolls back), wastes
// memory, and can't be replayed coherently. So while the alternate screen is active we DON'T
// cache: the pre-alt scrollback is frozen and preserved, and on reconnect the client just nudges
// the app (SIGWINCH) to repaint the current screen. On exit (…l) normal caching resumes.
function createLineBuffer(maxBytes) {
  return {
    lines: [],            // [{ data: string, bytes: number }]
    pending: '',          // partial line not yet terminated
    escState: 0,          // 0=normal 1=just saw ESC 2=CSI 3=OSC 5=string-ESC
    csiParams: '',        // CSI parameter bytes accumulated in escState 2 (to detect ?1049h/l)
    altScreen: false,     // true while on the alternate screen (don't cache)
    totalBytes: 0,
    firstLineIndex: 0,
    maxBytes,
    append(chunk) {
      let start = 0;
      for (let i = 0; i < chunk.length; i++) {
        const c = chunk.charCodeAt(i);
        switch (this.escState) {
          case 0:
            if (c === 0x1b) { this.escState = 1; }
            else if (c === 0x0a) {
              // safe newline: flush as one line — but only while NOT on the alternate screen.
              if (!this.altScreen) {
                const lineData = this.pending + chunk.slice(start, i + 1);
                this.lines.push({ data: lineData, bytes: lineData.length });
                this.totalBytes += lineData.length;
              }
              this.pending = '';
              start = i + 1;
            }
            break;
          case 1: // just saw ESC
            if (c === 0x5b) { this.escState = 2; this.csiParams = ''; } // [ → CSI
            else if (c === 0x5d) this.escState = 3;     // ] → OSC
            else if (c === 0x50 || c === 0x58 || c === 0x5e || c === 0x5f) this.escState = 3; // DCS/SOS/PM/APC
            else this.escState = 0;                     // short 2-byte escape; consumed
            break;
          case 2: // CSI: parameters then final byte 0x40–0x7e
            if (c >= 0x40 && c <= 0x7e) {
              // Alternate-screen toggle: CSI ?1049h / ?1047h / ?47h (enter), …l (exit).
              if (c === 0x68 /* h */ || c === 0x6c /* l */) {
                if (this.csiParams === '?1049' || this.csiParams === '?1047' || this.csiParams === '?47') {
                  const on = (c === 0x68);
                  if (on !== this.altScreen) {
                    // Demarcate cleanly at the toggle so pre/post-alt bytes don't mix.
                    this.pending = '';
                    start = i + 1;
                  }
                  this.altScreen = on;
                }
              }
              this.csiParams = '';
              this.escState = 0;
            } else if (this.csiParams.length < 24) {
              this.csiParams += chunk[i];
            }
            break;
          case 3: // OSC/string: ends at BEL (0x07) or ESC \\ (0x1b 0x5c)
            if (c === 0x07) this.escState = 0;
            else if (c === 0x1b) this.escState = 5;
            break;
          case 5:
            this.escState = (c === 0x5c) ? 0 : 0;       // either way exit string
            break;
        }
      }
      // tail goes to pending — but only while NOT on the alternate screen (alt output is dropped).
      if (start < chunk.length && !this.altScreen) this.pending += chunk.slice(start);

      // trim oldest while over budget
      while (this.totalBytes > this.maxBytes && this.lines.length > 1) {
        const dropped = this.lines.shift();
        this.totalBytes -= dropped.bytes;
        this.firstLineIndex++;
      }
    },
    snapshot() {
      return { firstLineIndex: this.firstLineIndex, lines: this.lines, pending: this.pending };
    },
    sliceAbs(fromAbs, count) {
      const localFrom = Math.max(0, fromAbs - this.firstLineIndex);
      const localTo = Math.min(this.lines.length, localFrom + count);
      return this.lines.slice(localFrom, localTo);
    },
    tailByBytes(targetBytes) {
      let acc = this.pending.length;
      let i = this.lines.length;
      while (i > 0 && acc < targetBytes) {
        i--;
        acc += this.lines[i].bytes;
      }
      return {
        startLine: this.firstLineIndex + i,
        endLine: this.firstLineIndex + this.lines.length,
        lines: this.lines.slice(i),
        pending: this.pending,
      };
    },
  };
}

module.exports = { createLineBuffer };
