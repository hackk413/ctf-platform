/**
 * CTF Atlas — Terminal Engine v2.0
 * Pure client-side ES6+ virtual terminal environment.
 * No backend. No Docker. Entirely browser-native.
 *
 * Exports: CTFTerminalEngine
 */

'use strict';

export class CTFTerminalEngine {
  /**
   * @param {Object} config
   * @param {HTMLElement} config.outputEl   - Element to write terminal output into
   * @param {HTMLInputElement} config.inputEl - Text input element
   * @param {HTMLElement} config.promptEl   - Prompt label element
   * @param {Object} config.challenge       - Challenge descriptor from live-intel.json
   * @param {Function} [config.onSolve]     - Callback invoked with flag string on success
   */
  constructor({ outputEl, inputEl, promptEl, challenge, onSolve }) {
    this.outputEl  = outputEl;
    this.inputEl   = inputEl;
    this.promptEl  = promptEl;
    this.challenge = challenge || {};
    this.onSolve   = onSolve   || (() => {});

    /* ── Core terminal state ── */
    this.history       = [];          // command history buffer
    this.historyIndex  = -1;          // current traversal position
    this.cwd           = '/home/ctf'; // current working directory
    this.user          = 'ctf';
    this.hostname      = 'atlas-lab';
    this.hintsUnlocked = 0;

    /* ── Persistence ── */
    const sk = `atlas-term-solved-${this.challenge.id || 'default'}`;
    this.storageKey = sk;
    this.solved     = localStorage.getItem(sk) === '1';

    /* ── Virtual filesystem ── */
    this.vfs = this._buildVFS(challenge.vfs || {});

    /* ── Custom command catalogue from challenge ── */
    this.customCommands = challenge.custom_commands || {};

    /* ── Environment variables ── */
    this.env = { PATH: '/usr/bin:/bin', USER: 'ctf', HOME: '/home/ctf' };

    /* ── Wire events ── */
    this._bindInput();
    this._updatePrompt();
    this._printWelcome();
  }

  /* ─────────────────────────────────────────────────────────────
   * PUBLIC API
   * ───────────────────────────────────────────────────────────── */

  /** Completely reset the terminal to initial state */
  reset() {
    this.cwd           = '/home/ctf';
    this.history       = [];
    this.historyIndex  = -1;
    this.hintsUnlocked = 0;
    this.vfs           = this._buildVFS(this.challenge.vfs || {});
    this.outputEl.innerHTML = '';
    this._updatePrompt();
    this._printWelcome();
    this._println('[RESET] Environment restored to initial state.', 'term-info');
  }

  /** Programmatically submit a command (used by hint system / tests) */
  exec(cmd) {
    if (!cmd.trim()) return;
    this._addHistory(cmd);
    this._printLine(`${this._promptString()}${cmd}`);
    const out = this._dispatch(cmd.trim());
    if (out) this._printRaw(out);
    this._updatePrompt();
    this._scrollBottom();
  }

  /* ─────────────────────────────────────────────────────────────
   * VIRTUAL FILESYSTEM
   * ───────────────────────────────────────────────────────────── */

  _buildVFS(seed) {
    /** Default file-system skeleton */
    const base = {
      '/': { type: 'dir', perm: 'drwxr-xr-x', owner: 'root', size: 4096, mtime: '2026-01-01 00:00' },
      '/bin': { type: 'dir', perm: 'drwxr-xr-x', owner: 'root', size: 4096, mtime: '2026-01-01 00:00' },
      '/usr': { type: 'dir', perm: 'drwxr-xr-x', owner: 'root', size: 4096, mtime: '2026-01-01 00:00' },
      '/usr/bin': { type: 'dir', perm: 'drwxr-xr-x', owner: 'root', size: 4096, mtime: '2026-01-01 00:00' },
      '/home': { type: 'dir', perm: 'drwxr-xr-x', owner: 'root', size: 4096, mtime: '2026-01-01 00:00' },
      '/home/ctf': { type: 'dir', perm: 'drwxr-x---', owner: 'ctf', size: 4096, mtime: '2026-09-30 10:00' },
      '/home/ctf/.bashrc': { type: 'file', perm: '-rw-r--r--', owner: 'ctf', size: 220, mtime: '2026-01-01 00:00', content: '# .bashrc\nexport PS1="\\u@\\h:\\w\\$ "\n' },
      '/tmp': { type: 'dir', perm: 'drwxrwxrwt', owner: 'root', size: 4096, mtime: '2026-09-30 09:55' },
      '/etc': { type: 'dir', perm: 'drwxr-xr-x', owner: 'root', size: 4096, mtime: '2026-01-01 00:00' },
      '/etc/passwd': { type: 'file', perm: '-rw-r--r--', owner: 'root', size: 1087, mtime: '2026-01-01 00:00',
        content: 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nctf:x:1000:1000:CTF User,,,:/home/ctf:/bin/bash\n' },
    };

    /* Overlay challenge-specific VFS nodes */
    for (const [path, node] of Object.entries(seed)) {
      base[path] = node;
    }
    return base;
  }

  _resolve(raw) {
    /* Resolve a path against cwd, handling . and .. */
    if (!raw || raw === '') return this.cwd;
    let p = raw.startsWith('/') ? raw : `${this.cwd}/${raw}`;
    const parts = p.split('/').filter(Boolean);
    const stack = [];
    for (const part of parts) {
      if (part === '..') stack.pop();
      else if (part !== '.') stack.push(part);
    }
    return '/' + stack.join('/');
  }

  _ls(path) {
    /* Return child entries of a directory path */
    const norm = path.endsWith('/') && path !== '/' ? path.slice(0, -1) : path;
    return Object.entries(this.vfs).filter(([k]) => {
      if (k === norm) return false;
      const parent = k.replace(/\/[^/]+$/, '') || '/';
      return parent === norm;
    });
  }

  _exists(path) { return Object.prototype.hasOwnProperty.call(this.vfs, path); }
  _isDir(path)  { return this._exists(path) && this.vfs[path].type === 'dir'; }
  _isFile(path) { return this._exists(path) && this.vfs[path].type === 'file'; }

  /* ─────────────────────────────────────────────────────────────
   * COMMAND DISPATCH
   * ───────────────────────────────────────────────────────────── */

  _dispatch(raw) {
    const tokens  = this._tokenize(raw);
    const cmd     = tokens[0] || '';
    const args    = tokens.slice(1);

    /* Check custom commands first */
    if (this.customCommands[cmd]) {
      return this._runCustomCommand(cmd, args);
    }

    switch (cmd) {
      case 'ls':        return this._cmdLs(args);
      case 'cd':        return this._cmdCd(args);
      case 'pwd':       return this._cmdPwd();
      case 'cat':       return this._cmdCat(args);
      case 'find':      return this._cmdFind(args);
      case 'file':      return this._cmdFile(args);
      case 'whoami':    return this._cmdWhoami();
      case 'id':        return this._cmdId();
      case 'uname':     return this._cmdUname(args);
      case 'strings':   return this._cmdStrings(args);
      case 'xxd':       return this._cmdXxd(args);
      case 'hexdump':   return this._cmdXxd(args);
      case 'exiftool':  return this._cmdExiftool(args);
      case 'binwalk':   return this._cmdBinwalk(args);
      case 'python3':
      case 'python':    return this._cmdPython(args);
      case 'openssl':   return this._cmdOpenssl(args);
      case 'echo':      return this._cmdEcho(args);
      case 'env':       return this._cmdEnv();
      case 'export':    return this._cmdExport(args);
      case 'mkdir':     return this._cmdMkdir(args);
      case 'touch':     return this._cmdTouch(args);
      case 'cp':        return this._cmdCp(args);
      case 'mv':        return this._cmdMv(args);
      case 'rm':        return this._cmdRm(args);
      case 'chmod':     return this._cmdChmod(args);
      case 'stat':      return this._cmdStat(args);
      case 'grep':      return this._cmdGrep(args);
      case 'head':      return this._cmdHead(args);
      case 'tail':      return this._cmdTail(args);
      case 'wc':        return this._cmdWc(args);
      case 'sort':      return this._cmdSort(args);
      case 'uniq':      return this._cmdUniq(args);
      case 'cut':       return this._cmdCut(args);
      case 'awk':       return this._cmdAwk(args);
      case 'sed':       return this._cmdSed(args);
      case 'base64':    return this._cmdBase64(args);
      case 'clear':     this.outputEl.innerHTML = ''; return '';
      case 'help':      return this._cmdHelp();
      case 'hint':      return this._cmdHint(args);
      case 'submit':    return this._cmdSubmit(args);
      case 'reset':     this.reset(); return '';
      case 'history':   return this.history.map((h,i)=>`  ${String(i+1).padStart(4)}  ${h}`).join('\n');
      default:
        return `<span class="term-err">bash: ${this._esc(cmd)}: command not found</span>`;
    }
  }

  _tokenize(raw) {
    /* Simple shell tokenizer: handles quoted strings */
    const tokens = [];
    let cur = '';
    let inSingle = false, inDouble = false;
    for (let i = 0; i < raw.length; i++) {
      const c = raw[i];
      if (c === "'" && !inDouble) { inSingle = !inSingle; continue; }
      if (c === '"' && !inSingle) { inDouble = !inDouble; continue; }
      if (c === ' ' && !inSingle && !inDouble) {
        if (cur) { tokens.push(cur); cur = ''; }
        continue;
      }
      cur += c;
    }
    if (cur) tokens.push(cur);
    return tokens;
  }

  _runCustomCommand(cmd, args) {
    const def = this.customCommands[cmd];
    if (typeof def === 'function') return def(args, this);
    if (typeof def === 'string')   return def;
    if (Array.isArray(def)) {
      const joined = args.join(' ');
      for (const item of def) {
        if (!item.match || joined.includes(item.match)) {
          return item.output;
        }
      }
      return def[def.length - 1]?.output || '';
    }
    /* Object: { output, condition, args_match } */
    if (def && typeof def === 'object') {
      if (def.args_match) {
        const joined = args.join(' ');
        if (!joined.includes(def.args_match)) {
          return def.wrong_args || `Usage: ${cmd} ${def.args_match}`;
        }
      }
      return def.output || '';
    }
    return '';
  }

  /* ─────────────────────────────────────────────────────────────
   * BUILT-IN COMMANDS
   * ───────────────────────────────────────────────────────────── */

  _cmdLs(args) {
    let showAll = false, longFormat = false, inode = false;
    const paths = [];
    for (const a of args) {
      if (a.startsWith('-')) {
        if (a.includes('a')) showAll    = true;
        if (a.includes('l')) longFormat = true;
        if (a.includes('i')) inode      = true;
      } else paths.push(a);
    }
    const target = paths.length ? this._resolve(paths[0]) : this.cwd;
    if (!this._exists(target)) return `<span class="term-err">ls: cannot access '${this._esc(target)}': No such file or directory</span>`;

    let entries;
    if (this._isDir(target)) {
      entries = this._ls(target);
      if (!showAll) entries = entries.filter(([k]) => !k.split('/').pop().startsWith('.'));
    } else {
      entries = [[target, this.vfs[target]]];
    }

    if (!longFormat) {
      const names = entries.map(([k, v]) => {
        const name = k.split('/').pop();
        const cls  = v.type === 'dir' ? 'term-dir' : v.perm?.includes('s') ? 'term-suid' : 'term-file';
        return `<span class="${cls}">${this._esc(name)}${v.type === 'dir' ? '/' : ''}</span>`;
      });
      return names.join('  ') || '';
    }

    /* Long format */
    const lines = entries.map(([k, v]) => {
      const name   = k.split('/').pop();
      const perm   = v.perm   || (v.type === 'dir' ? 'drwxr-xr-x' : '-rw-r--r--');
      const owner  = v.owner  || 'ctf';
      const size   = String(v.size  || 0).padStart(8);
      const mtime  = v.mtime  || '2026-09-30 10:00';
      const inoNum = inode ? (Math.abs(this._hashStr(k)) % 999999 + 100000) + ' ' : '';
      const cls    = v.type === 'dir' ? 'term-dir' : perm.includes('s') ? 'term-suid' : 'term-file';
      return `${inoNum}${perm} 1 ${owner.padEnd(8)} ${owner.padEnd(8)} ${size} ${mtime} <span class="${cls}">${this._esc(name)}${v.type === 'dir' ? '/' : ''}</span>`;
    });
    return 'total ' + entries.length + '\n' + lines.join('\n');
  }

  _cmdCd(args) {
    const dest = args[0] ? this._resolve(args[0]) : '/home/ctf';
    if (!this._exists(dest))  return `<span class="term-err">bash: cd: ${this._esc(dest)}: No such file or directory</span>`;
    if (!this._isDir(dest))   return `<span class="term-err">bash: cd: ${this._esc(dest)}: Not a directory</span>`;
    this.cwd = dest;
    this._updatePrompt();
    return '';
  }

  _cmdPwd() { return this.cwd; }

  _cmdCat(args) {
    if (!args.length) return '<span class="term-err">cat: missing operand</span>';
    const results = [];
    for (const a of args) {
      const p = this._resolve(a);
      if (!this._exists(p)) { results.push(`<span class="term-err">cat: ${this._esc(a)}: No such file or directory</span>`); continue; }
      if (this._isDir(p))   { results.push(`<span class="term-err">cat: ${this._esc(a)}: Is a directory</span>`); continue; }
      results.push(this._esc(this.vfs[p].content || ''));
    }
    return results.join('\n');
  }

  _cmdFind(args) {
    /* find [path] [-name pattern] [-perm -4000] [-type f|d] [-exec cmd \;] */
    let searchRoot   = this.cwd;
    let namePattern  = null;
    let permFilter   = null;
    let typeFilter   = null;
    let maxDepth     = Infinity;
    let i = 0;

    /* First positional arg is the search root if not a flag */
    if (args[0] && !args[0].startsWith('-')) { searchRoot = this._resolve(args[0]); i = 1; }

    while (i < args.length) {
      const flag = args[i++];
      if (flag === '-name')     { namePattern = args[i++]; }
      else if (flag === '-perm') { permFilter = args[i++]; }
      else if (flag === '-type') { typeFilter = args[i++]; }
      else if (flag === '-maxdepth') { maxDepth = parseInt(args[i++], 10) || 0; }
      else if (flag === '-exec') { /* consume until \; */ while (i < args.length && args[i++] !== '\\;') {} }
    }

    const results = [];
    const rootDepth = searchRoot.split('/').filter(Boolean).length;

    for (const [path, node] of Object.entries(this.vfs)) {
      if (!path.startsWith(searchRoot === '/' ? '/' : searchRoot + '/') && path !== searchRoot) continue;
      const depth = path.split('/').filter(Boolean).length - rootDepth;
      if (depth > maxDepth) continue;

      /* Type filter */
      if (typeFilter === 'f' && node.type !== 'file') continue;
      if (typeFilter === 'd' && node.type !== 'dir')  continue;

      /* Name pattern (glob-lite: only * wildcard) */
      if (namePattern) {
        const fname = path.split('/').pop();
        const regex = new RegExp('^' + namePattern.replace(/\./g, '\\.').replace(/\*/g, '.*') + String.fromCharCode(36));
        if (!regex.test(fname)) continue;
      }

      /* Perm filter: -4000 = SUID bit */
      if (permFilter) {
        const perm = node.perm || '';
        if (permFilter === '-4000' || permFilter === '-u+s') {
          if (!perm.includes('s') && !perm.includes('S')) continue;
        }
        if (permFilter === '-2000') {
          if (!perm.includes('s') && !perm.includes('S')) continue;
        }
      }

      const cls = node.type === 'dir' ? 'term-dir' : (node.perm||'').includes('s') ? 'term-suid' : 'term-file';
      results.push(`<span class="${cls}">${this._esc(path)}</span>`);
    }

    return results.join('\n') || '';
  }

  _cmdFile(args) {
    if (!args.length) return '<span class="term-err">file: missing operand</span>';
    return args.map(a => {
      const p = this._resolve(a);
      if (!this._exists(p)) return `${a}: ERROR: cannot open \`${a}' (No such file or directory)`;
      const node = this.vfs[p];
      if (node.type === 'dir') return `${a}: directory`;
      const magic = node.magic || node.file_type || 'ASCII text';
      return `${a}: ${magic}`;
    }).join('\n');
  }

  _cmdWhoami() { return this.user; }

  _cmdId() {
    const uid = this.user === 'root' ? 0 : 1000;
    return `uid=${uid}(${this.user}) gid=${uid}(${this.user}) groups=${uid}(${this.user})`;
  }

  _cmdUname(args) {
    if (args.includes('-a')) return 'Linux atlas-lab 5.15.0-atlas #1 SMP x86_64 GNU/Linux';
    if (args.includes('-r')) return '5.15.0-atlas';
    if (args.includes('-s')) return 'Linux';
    return 'Linux';
  }

  _cmdStrings(args) {
    const minLen = (() => {
      const ni = args.indexOf('-n');
      return ni >= 0 ? parseInt(args[ni+1], 10) || 4 : 4;
    })();
    const files  = args.filter(a => !a.startsWith('-') && !/^\d+$/.test(a));
    if (!files.length) return '<span class="term-err">strings: missing operand</span>';

    const results = [];
    for (const a of files) {
      const p = this._resolve(a);
      if (!this._exists(p)) { results.push(`<span class="term-err">strings: ${this._esc(a)}: No such file or directory</span>`); continue; }
      const node = this.vfs[p];
      if (node.strings) { results.push(node.strings.join('\n')); continue; }
      if (node.content) {
        const matches = (node.content.match(/[^\x00-\x1F\x7F-\xFF]{4,}/g) || []);
        results.push(matches.filter(m => m.length >= minLen).join('\n'));
      }
    }
    return results.join('\n');
  }

  _cmdXxd(args) {
    const files = args.filter(a => !a.startsWith('-'));
    if (!files.length) return '<span class="term-err">xxd: missing operand</span>';
    const p    = this._resolve(files[0]);
    if (!this._exists(p)) return `<span class="term-err">xxd: ${this._esc(files[0])}: No such file or directory</span>`;
    const node = this.vfs[p];
    if (node.hex_dump) return `<span class="term-output">${this._esc(node.hex_dump)}</span>`;
    /* Generate a fake hex dump of content */
    const content = node.content || '';
    const bytes   = [...content].map(c => c.charCodeAt(0));
    const lines   = [];
    for (let off = 0; off < Math.min(bytes.length, 256); off += 16) {
      const chunk = bytes.slice(off, off + 16);
      const hex   = chunk.map(b => b.toString(16).padStart(2,'0')).join(' ');
      const ascii = chunk.map(b => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.').join('');
      lines.push(`${off.toString(16).padStart(8,'0')}: ${hex.padEnd(47)}  ${ascii}`);
    }
    if (bytes.length > 256) lines.push(`... (${bytes.length - 256} more bytes)`);
    return `<span class="term-output">${this._esc(lines.join('\n'))}</span>`;
  }

  _cmdExiftool(args) {
    const files = args.filter(a => !a.startsWith('-'));
    if (!files.length) return '<span class="term-err">exiftool: missing operand</span>';

    const flagAll   = args.includes('-all') || args.includes('-a');
    const flagGps   = args.includes('-gps:all');
    const flagStrip = args.some(a => a.startsWith('-all='));

    const results = [];
    for (const a of files) {
      const p = this._resolve(a);
      if (!this._exists(p)) { results.push(`exiftool: Error: File not found - ${a}`); continue; }
      const node  = this.vfs[p];
      const exif  = node.exif || {};
      if (!Object.keys(exif).length) { results.push(`${a}: No EXIF data found`); continue; }

      const header = `======== ${a}`;
      results.push(header);
      const toShow = flagGps
        ? Object.fromEntries(Object.entries(exif).filter(([k]) => k.toLowerCase().includes('gps')))
        : flagAll ? exif : Object.fromEntries(Object.entries(exif).slice(0, 12));

      for (const [k, v] of Object.entries(toShow)) {
        results.push(`${k.padEnd(32)}: ${v}`);
      }
    }
    return `<span class="term-output">${this._esc(results.join('\n'))}</span>`;
  }

  _cmdBinwalk(args) {
    const extractMode = args.includes('-e') || args.includes('--extract');
    const entropyMode = args.includes('-E') || args.includes('--entropy');
    const files = args.filter(a => !a.startsWith('-'));
    if (!files.length) return '<span class="term-err">binwalk: missing operand</span>';

    const results = [];
    for (const a of files) {
      const p = this._resolve(a);
      if (!this._exists(p)) { results.push(`<span class="term-err">binwalk: ${this._esc(a)}: No such file or directory</span>`); continue; }
      const node = this.vfs[p];

      if (node.binwalk_output) {
        results.push(node.binwalk_output);
      } else {
        results.push(`DECIMAL       HEXADECIMAL     DESCRIPTION\n` +
          `--------------------------------------------------------------------------------\n` +
          `0             0x0             ${node.magic || 'Data'}, size: ${node.size || 0} bytes`);
      }

      if (extractMode && node.binwalk_extract) {
        /* Inject extracted files into VFS */
        for (const [xPath, xNode] of Object.entries(node.binwalk_extract)) {
          const resolved = this._resolve(xPath);
          this.vfs[resolved] = xNode;
        }
        results.push(`\nExtracted files to: _${a}.extracted/`);
      }

      if (entropyMode && node.entropy_output) {
        results.push(node.entropy_output);
      }
    }
    return `<span class="term-output">${results.join('\n\n')}</span>`;
  }

  _cmdPython(args) {
    /* Minimal Python interpreter stubs for CTF-relevant operations */
    const cArg = args.indexOf('-c');
    if (cArg < 0) return `Python 3.11.0 (atlas-lab)\nType "help", "copyright" for more information.`;

    const code = args.slice(cArg + 1).join(' ');

    /* --- RSA math stubs --- */
    const rsaDecrypt = code.match(/pow\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)/);
    if (rsaDecrypt) {
      const [, cStr, dStr, nStr] = rsaDecrypt;
      try {
        const c = BigInt(cStr), d = BigInt(dStr), n = BigInt(nStr);
        const m = this._modpow(c, d, n);
        /* Try to decode as ASCII */
        let result = m.toString();
        try {
          const hex = m.toString(16).padStart(result.length % 2 ? result.length + 1 : result.length, '0');
          const bytes = hex.match(/.{2}/g).map(b => parseInt(b, 16));
          const text  = bytes.map(b => String.fromCharCode(b)).join('');
          if (text.match(/^[\x20-\x7e]+$/)) result = `${m}\n# as ASCII: '${text}'`;
        } catch (_) {}
        return result;
      } catch (_) {}
    }

    /* --- Base64 --- */
    const b64d = code.match(/base64\.b64decode\(['"]([^'"]+)['"]\)/);
    if (b64d) {
      try { return atob(b64d[1]); } catch (_) {}
    }

    /* --- Hex decode --- */
    const hexDec = code.match(/bytes\.fromhex\(['"]([^'"]+)['"]\)\.decode\(\)/);
    if (hexDec) {
      try {
        const hex  = hexDec[1].replace(/\s/g,'');
        const text = hex.match(/.{2}/g).map(b => String.fromCharCode(parseInt(b, 16))).join('');
        return text;
      } catch (_) {}
    }

    /* --- Integer cube root (RSA e=3 attack) --- */
    const cbrt = code.match(/round\(c\s*\*\*\s*\(1\/3\)\)|int\(c\*\*\(1\/3\)\)/);
    if (cbrt && this.challenge.python_context) {
      return this.challenge.python_context.cube_root_result || '(result depends on challenge values)';
    }

    /* --- Print statements --- */
    const printM = code.match(/^print\(['"](.+)['"]\)$/);
    if (printM) return printM[1];

    return `<span class="term-info">[python3] Statement evaluated (simulated environment)</span>`;
  }

  _cmdOpenssl(args) {
    const sub = args[0];
    if (sub === 'rsa') {
      if (args.includes('-text') && args.includes('-noout')) {
        const inIdx = args.indexOf('-in');
        if (inIdx >= 0) {
          const p = this._resolve(args[inIdx + 1] || '');
          if (this._exists(p) && this.vfs[p].openssl_rsa_text) {
            return `<span class="term-output">${this._esc(this.vfs[p].openssl_rsa_text)}</span>`;
          }
        }
        return 'unable to load key';
      }
    }
    if (sub === 'prime' && args.includes('-generate')) {
      return '(prime generation simulated — use python3 -c "from Crypto.Util.number import getPrime; print(getPrime(512))")';
    }
    if (sub === 'enc' || sub === 'dgst') {
      return '<span class="term-info">[openssl] Encryption/hash operations simulated in this environment.</span>';
    }
    return `<span class="term-info">OpenSSL 3.2.0 (CTF Atlas simulated)</span>`;
  }

  _cmdEcho(args) {
    const noNewline = args[0] === '-n';
    const text      = (noNewline ? args.slice(1) : args).join(' ');
    /* Expand simple $VAR */
    const expanded  = text.replace(/\$(\w+)/g, (_, k) => this.env[k] ?? '');
    return this._esc(expanded);
  }

  _cmdEnv() {
    return Object.entries(this.env).map(([k,v]) => `${k}=${v}`).join('\n');
  }

  _cmdExport(args) {
    for (const a of args) {
      const eq = a.indexOf('=');
      if (eq >= 0) this.env[a.slice(0, eq)] = a.slice(eq + 1);
    }
    return '';
  }

  _cmdMkdir(args) {
    const p = args.filter(a => !a.startsWith('-'));
    for (const d of p) {
      const full = this._resolve(d);
      if (this._exists(full)) { this._println(`mkdir: cannot create directory '${this._esc(d)}': File exists`, 'term-err'); continue; }
      this.vfs[full] = { type: 'dir', perm: 'drwxr-xr-x', owner: this.user, size: 4096, mtime: new Date().toISOString().slice(0,16).replace('T',' ') };
    }
    return '';
  }

  _cmdTouch(args) {
    for (const a of args) {
      const p = this._resolve(a);
      if (!this._exists(p)) {
        this.vfs[p] = { type: 'file', perm: '-rw-r--r--', owner: this.user, size: 0, mtime: new Date().toISOString().slice(0,16).replace('T',' '), content: '' };
      } else {
        this.vfs[p].mtime = new Date().toISOString().slice(0,16).replace('T',' ');
      }
    }
    return '';
  }

  _cmdCp(args) {
    if (args.length < 2) return '<span class="term-err">cp: missing destination operand</span>';
    const src  = this._resolve(args[0]);
    const dest = this._resolve(args[1]);
    if (!this._exists(src)) return `<span class="term-err">cp: cannot stat '${this._esc(args[0])}': No such file or directory</span>`;
    this.vfs[dest] = { ...this.vfs[src] };
    return '';
  }

  _cmdMv(args) {
    if (args.length < 2) return '<span class="term-err">mv: missing destination operand</span>';
    const src  = this._resolve(args[0]);
    const dest = this._resolve(args[1]);
    if (!this._exists(src)) return `<span class="term-err">mv: cannot stat '${this._esc(args[0])}': No such file or directory</span>`;
    this.vfs[dest] = { ...this.vfs[src] };
    delete this.vfs[src];
    return '';
  }

  _cmdRm(args) {
    const force     = args.includes('-f');
    const recursive = args.includes('-r') || args.includes('-rf') || args.includes('-fr');
    const targets   = args.filter(a => !a.startsWith('-'));
    for (const t of targets) {
      const p = this._resolve(t);
      if (!this._exists(p)) {
        if (!force) return `<span class="term-err">rm: cannot remove '${this._esc(t)}': No such file or directory</span>`;
        continue;
      }
      if (this._isDir(p) && !recursive) return `<span class="term-err">rm: cannot remove '${this._esc(t)}': Is a directory</span>`;
      if (recursive) {
        for (const k of Object.keys(this.vfs)) {
          if (k === p || k.startsWith(p + '/')) delete this.vfs[k];
        }
      } else {
        delete this.vfs[p];
      }
    }
    return '';
  }

  _cmdChmod(args) {
    if (args.length < 2) return '<span class="term-err">chmod: missing operand</span>';
    const mode = args[0];
    const p    = this._resolve(args[1]);
    if (!this._exists(p)) return `<span class="term-err">chmod: cannot access '${this._esc(args[1])}': No such file or directory</span>`;
    /* Simulate permission update */
    const node = this.vfs[p];
    const oct  = parseInt(mode, 8);
    if (!isNaN(oct)) {
      const bits = ['---','--x','-w-','-wx','r--','r-x','rw-','rwx'];
      const u = bits[(oct >> 6) & 7], g = bits[(oct >> 3) & 7], o = bits[oct & 7];
      const type = node.type === 'dir' ? 'd' : '-';
      node.perm = `${type}${u}${g}${o}`;
    }
    return '';
  }

  _cmdStat(args) {
    if (!args.length) return '<span class="term-err">stat: missing operand</span>';
    const p = this._resolve(args[0]);
    if (!this._exists(p)) return `<span class="term-err">stat: cannot statx '${this._esc(args[0])}': No such file or directory</span>`;
    const n = this.vfs[p];
    const ino = Math.abs(this._hashStr(p)) % 999999 + 100000;
    return `  File: ${p}\n  Size: ${n.size || 0}\tBlocks: ${Math.ceil((n.size||0)/512)}\t\tIO Block: 4096   ${n.type === 'dir' ? 'directory' : 'regular file'}\nDevice: fd00h/${ino}d\tInode: ${ino}    Links: 1\nAccess: ${n.perm || '-rw-r--r--'} Uid: (1000/${n.owner || 'ctf'})   Gid: (1000/${n.owner || 'ctf'})\nModify: ${n.mtime || '2026-09-30 10:00'}\nChange: ${n.ctime || n.mtime || '2026-09-30 10:00'}`;
  }

  _cmdGrep(args) {
    let pattern = null, caseInsensitive = false, lineNumbers = false;
    const files = [];
    let i = 0;
    while (i < args.length) {
      const a = args[i++];
      if (a === '-i') { caseInsensitive = true; continue; }
      if (a === '-n') { lineNumbers = true; continue; }
      if (a === '-r' || a === '-l' || a === '-c') { continue; }
      if (a.startsWith('-')) continue;
      if (!pattern) { pattern = a; continue; }
      files.push(a);
    }
    if (!pattern) return '<span class="term-err">grep: missing pattern</span>';
    const regex = new RegExp(pattern.replace(/[.*+?^${}()|[\]\\]/g, (m) => '\\' + m), caseInsensitive ? 'gi' : 'g');

    const results = [];
    for (const f of files) {
      const p    = this._resolve(f);
      const node = this.vfs[p];
      if (!node || !node.content) continue;
      const lines = node.content.split('\n');
      lines.forEach((line, idx) => {
        if (regex.test(line)) {
          results.push(lineNumbers ? `${idx+1}:${line}` : line);
        }
        regex.lastIndex = 0;
      });
    }
    return results.join('\n');
  }

  _cmdHead(args) {
    const n  = args.includes('-n') ? parseInt(args[args.indexOf('-n')+1],10) : 10;
    const fs = args.filter(a => !a.startsWith('-') && !/^\d+$/.test(a));
    if (!fs.length) return '<span class="term-err">head: missing operand</span>';
    const p = this._resolve(fs[0]);
    if (!this._exists(p)) return `<span class="term-err">head: cannot open '${this._esc(fs[0])}': No such file or directory</span>`;
    return (this.vfs[p].content || '').split('\n').slice(0, n).join('\n');
  }

  _cmdTail(args) {
    const n  = args.includes('-n') ? parseInt(args[args.indexOf('-n')+1],10) : 10;
    const fs = args.filter(a => !a.startsWith('-') && !/^\d+$/.test(a));
    if (!fs.length) return '<span class="term-err">tail: missing operand</span>';
    const p = this._resolve(fs[0]);
    if (!this._exists(p)) return `<span class="term-err">tail: cannot open '${this._esc(fs[0])}': No such file or directory</span>`;
    const lines = (this.vfs[p].content || '').split('\n');
    return lines.slice(-n).join('\n');
  }

  _cmdWc(args) {
    const flags = args.filter(a => a.startsWith('-'));
    const files = args.filter(a => !a.startsWith('-'));
    if (!files.length) return '<span class="term-err">wc: missing operand</span>';
    const results = [];
    for (const f of files) {
      const p = this._resolve(f);
      if (!this._exists(p)) { results.push(`wc: ${f}: No such file or directory`); continue; }
      const c = this.vfs[p].content || '';
      const lines = c.split('\n').length;
      const words = c.split(/\s+/).filter(Boolean).length;
      const chars = c.length;
      if (flags.includes('-l')) results.push(`${lines} ${f}`);
      else if (flags.includes('-w')) results.push(`${words} ${f}`);
      else if (flags.includes('-c')) results.push(`${chars} ${f}`);
      else results.push(`${lines} ${words} ${chars} ${f}`);
    }
    return results.join('\n');
  }

  _cmdSort(args) {
    const files = args.filter(a => !a.startsWith('-'));
    const unique = args.includes('-u');
    if (!files.length) return '';
    const p = this._resolve(files[0]);
    if (!this._exists(p)) return `<span class="term-err">sort: cannot read: No such file or directory</span>`;
    let lines = (this.vfs[p].content || '').split('\n').filter(Boolean).sort();
    if (unique) lines = [...new Set(lines)];
    return lines.join('\n');
  }

  _cmdUniq(args) {
    const files = args.filter(a => !a.startsWith('-'));
    if (!files.length) return '';
    const p = this._resolve(files[0]);
    if (!this._exists(p)) return `<span class="term-err">uniq: no such file</span>`;
    const lines = (this.vfs[p].content || '').split('\n');
    const result = [];
    for (let i = 0; i < lines.length; i++) {
      if (i === 0 || lines[i] !== lines[i-1]) result.push(lines[i]);
    }
    return result.join('\n');
  }

  _cmdCut(args) {
    /* cut -d DELIM -f FIELD FILE */
    const dIdx = args.indexOf('-d');
    const fIdx = args.indexOf('-f');
    const delim = dIdx >= 0 ? (args[dIdx+1] || '\t') : '\t';
    const field = fIdx >= 0 ? (parseInt(args[fIdx+1],10) - 1) : 0;
    const files = args.filter(a => !a.startsWith('-'));
    if (!files.length) return '';
    const p = this._resolve(files[0]);
    if (!this._exists(p)) return '';
    return (this.vfs[p].content || '').split('\n').map(l => l.split(delim)[field] || '').join('\n');
  }

  _cmdAwk(args) {
    /* Minimal awk: single pattern { action } */
    const prog   = args[0] || '';
    const files  = args.slice(1).filter(a => !a.startsWith('-'));
    const printM = prog.match(/^\{print\s+\$(\d+)\}$/) || prog.match(/^\{print\s+\$(\d+)\s*\}$/);
    if (!files.length || !printM) return `<span class="term-info">[awk] Limited simulation — basic field printing only.</span>`;
    const field = parseInt(printM[1], 10) - 1;
    const p = this._resolve(files[0]);
    if (!this._exists(p)) return '';
    return (this.vfs[p].content || '').split('\n').map(l => l.split(/\s+/)[field] || '').join('\n');
  }

  _cmdSed(args) {
    /* sed 's/old/new/g' file */
    const expr  = args[0] || '';
    const files = args.slice(1).filter(a => !a.startsWith('-'));
    const match = expr.match(/^s\/(.*)\/(.*)\/(g?)$/);
    if (!match || !files.length) return `<span class="term-info">[sed] Substitution simulation only: sed 's/old/new/g' file</span>`;
    const [, from, to, flags] = match;
    const regex = new RegExp(from, flags);
    const p = this._resolve(files[0]);
    if (!this._exists(p)) return `<span class="term-err">sed: ${files[0]}: No such file or directory</span>`;
    return (this.vfs[p].content || '').replace(regex, to);
  }

  _cmdBase64(args) {
    const decode = args.includes('-d') || args.includes('--decode');
    const files  = args.filter(a => !a.startsWith('-'));
    if (files.length) {
      const p = this._resolve(files[0]);
      if (!this._exists(p)) return `<span class="term-err">base64: ${files[0]}: No such file or directory</span>`;
      const content = this.vfs[p].content || '';
      try { return decode ? atob(content.trim()) : btoa(content); }
      catch (_) { return '<span class="term-err">base64: invalid input</span>'; }
    }
    return `<span class="term-info">base64: reading from stdin is not supported in this environment. Use: base64 &lt;filename&gt;</span>`;
  }

  _cmdHint(args) {
    const hints  = this.challenge.hints || [];
    const idx    = args[0] ? parseInt(args[0], 10) - 1 : this.hintsUnlocked;
    if (!hints.length) return '<span class="term-info">No hints available for this challenge.</span>';
    if (idx >= hints.length) return `<span class="term-info">All ${hints.length} hint(s) already unlocked.</span>`;
    this.hintsUnlocked = Math.max(this.hintsUnlocked, idx + 1);
    return `<span class="term-hint">💡 HINT ${idx+1}/${hints.length}: ${this._esc(hints[idx])}</span>`;
  }

  _cmdSubmit(args) {
    const submitted = args.join(' ').trim();
    const expected  = (this.challenge.flag || '').trim();
    if (!submitted) return '<span class="term-err">Usage: submit CTF{your_flag_here}</span>';
    if (submitted === expected) {
      localStorage.setItem(this.storageKey, '1');
      this.solved = true;
      this.onSolve(submitted);
      return `<span class="term-success">✓ CORRECT! Flag accepted: ${this._esc(submitted)}\n🏆 Challenge solved! Progress saved.</span>`;
    }
    return `<span class="term-err">✗ Incorrect flag. Keep investigating.\nSubmitted: ${this._esc(submitted)}</span>`;
  }

  _cmdHelp() {
    return `<span class="term-help">
═══════════════════════════════════════════════════════════
 CTF ATLAS — Virtual Terminal Environment
 Available Commands:
═══════════════════════════════════════════════════════════
 NAVIGATION    ls [-la] [-i]     List directory contents
               cd [path]         Change directory
               pwd               Print working directory
 FILE OPS      cat [file...]     Print file contents
               find [path] [expr] Search files (-perm -4000 -type f -name)
               stat [file]       File metadata
               file [file]       Identify file type
               strings [file]    Extract printable strings
               xxd [file]        Hex dump
 TOOLS         exiftool [opts] [file]  EXIF/metadata analysis
               binwalk [-e] [-E] [file] Firmware/embedded analysis
               python3 -c "code"  Run Python snippet
               openssl [sub] [opts]  Cryptographic operations
               base64 [-d] [file]  Encode/decode Base64
 TEXT          grep [-in] PATTERN [file]  Pattern search
               head/tail [-n N] [file]    First/last N lines
               cut [-d DELIM -f FIELD]    Field extraction
               awk '{print $N}' [file]    Field printing
               sed 's/x/y/g' [file]       Substitution
               wc [-l|-w|-c] [file]       Word/line count
               sort [-u] [file]  Sort lines
               uniq [file]       Deduplicate adjacent lines
 ENV           echo [text]       Print text
               env               Show environment variables
               export VAR=value  Set environment variable
 CTF SPECIFIC  hint [N]          Reveal hint N
               submit FLAG       Submit your flag
               history           Command history
               reset             Reset terminal environment
               help              This help text
═══════════════════════════════════════════════════════════
 Tip: Use ↑/↓ arrows to navigate command history.
 Tip: type 'hint' to reveal the first available hint.
═══════════════════════════════════════════════════════════
    </span>`;
  }

  /* ─────────────────────────────────────────────────────────────
   * OUTPUT & RENDERING
   * ───────────────────────────────────────────────────────────── */

  _printWelcome() {
    const title   = this.challenge.title || 'CTF Terminal Lab';
    const desc    = this.challenge.description || 'Investigate the virtual environment to find the flag.';
    const hCount  = (this.challenge.hints || []).length;
    const solved  = this.solved ? '\n<span class="term-success">✓ Challenge previously solved!</span>' : '';

    this._printRaw(`<span class="term-banner">
╔══════════════════════════════════════════════════════════╗
║        CTF ATLAS — Virtual Terminal Lab                  ║
╚══════════════════════════════════════════════════════════╝
</span><span class="term-info">Challenge: ${this._esc(title)}
${this._esc(desc)}
Hints available: ${hCount}  |  Type 'help' for commands  |  'hint' for first hint
</span>${solved}`);
  }

  _printLine(html) {
    const div = document.createElement('div');
    div.className = 'term-line';
    div.innerHTML = html;
    this.outputEl.appendChild(div);
  }

  _println(text, cls = '') {
    const div = document.createElement('div');
    div.className = `term-line ${cls}`;
    div.textContent = text;
    this.outputEl.appendChild(div);
  }

  _printRaw(html) {
    const div = document.createElement('div');
    div.className = 'term-line';
    div.innerHTML = html;
    this.outputEl.appendChild(div);
  }

  _scrollBottom() {
    const el = this.outputEl.parentElement || this.outputEl;
    el.scrollTop = el.scrollHeight;
  }

  _updatePrompt() {
    if (!this.promptEl) return;
    const cwd = this.cwd === `/home/${this.user}` ? '~' : this.cwd;
    this.promptEl.textContent = `${this.user}@${this.hostname}:${cwd}$ `;
  }

  _promptString() {
    const cwd = this.cwd === `/home/${this.user}` ? '~' : this.cwd;
    return `<span class="term-prompt">${this.user}@${this.hostname}:${cwd}$ </span>`;
  }

  /* ─────────────────────────────────────────────────────────────
   * INPUT BINDING
   * ───────────────────────────────────────────────────────────── */

  _bindInput() {
    if (!this.inputEl) return;

    this.inputEl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const cmd = this.inputEl.value;
        this.inputEl.value = '';
        this.historyIndex  = -1;
        this.exec(cmd);
        return;
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        this._navigateHistory(1);
        return;
      }
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        this._navigateHistory(-1);
        return;
      }
      if (e.key === 'Tab') {
        e.preventDefault();
        this._tabComplete();
        return;
      }
      if (e.key === 'l' && e.ctrlKey) {
        e.preventDefault();
        this.outputEl.innerHTML = '';
        return;
      }
    });
  }

  _addHistory(cmd) {
    if (!cmd.trim()) return;
    if (this.history[0] === cmd) return;
    this.history.unshift(cmd);
    if (this.history.length > 200) this.history.pop();
  }

  _navigateHistory(dir) {
    if (!this.history.length) return;
    this.historyIndex = Math.max(-1, Math.min(this.history.length - 1, this.historyIndex + dir));
    this.inputEl.value = this.historyIndex < 0 ? '' : this.history[this.historyIndex];
    /* move cursor to end */
    setTimeout(() => {
      this.inputEl.selectionStart = this.inputEl.selectionEnd = this.inputEl.value.length;
    }, 0);
  }

  _tabComplete() {
    const partial = this.inputEl.value;
    const tokens  = partial.split(' ');
    if (tokens.length <= 1) return;  // only complete arguments for now
    const last    = tokens[tokens.length - 1];
    const prefix  = this._resolve(last);
    const parent  = prefix.replace(/\/[^/]*$/, '') || '/';
    const stub    = prefix.split('/').pop();
    const matches = Object.keys(this.vfs).filter(k => {
      const p = k.replace(/\/[^/]*$/, '') || '/';
      return p === parent && k.split('/').pop().startsWith(stub);
    });
    if (matches.length === 1) {
      tokens[tokens.length - 1] = matches[0] + (this._isDir(matches[0]) ? '/' : '');
      this.inputEl.value = tokens.join(' ');
    } else if (matches.length > 1) {
      this._printRaw(matches.map(m => m.split('/').pop()).join('  '));
    }
  }

  /* ─────────────────────────────────────────────────────────────
   * UTILITIES
   * ───────────────────────────────────────────────────────────── */

  _esc(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  _hashStr(s) {
    let h = 0x811c9dc5;
    for (let i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h  = (h * 0x01000193) >>> 0;
    }
    return h;
  }

  /** BigInt modular exponentiation */
  _modpow(base, exp, mod) {
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
      if (exp % 2n === 1n) result = (result * base) % mod;
      exp  >>= 1n;
      base  = (base * base) % mod;
    }
    return result;
  }
}

/**
 * Factory: mount a CTFTerminalEngine into an existing container element.
 *
 * @param {HTMLElement} container  - The wrapper element for the terminal
 * @param {Object}      challenge  - Challenge descriptor (from live-intel.json)
 * @param {Function}    [onSolve] - Called with flag when challenge is solved
 * @returns {CTFTerminalEngine}
 */
export function mountTerminal(container, challenge, onSolve) {
  container.innerHTML = `
    <div class="vterm" aria-label="Virtual terminal for ${(challenge.title||'CTF lab').replace(/"/g,'&quot;')}">
      <div class="vterm-topbar">
        <span class="vterm-dot vterm-dot-red"></span>
        <span class="vterm-dot vterm-dot-amber"></span>
        <span class="vterm-dot vterm-dot-green"></span>
        <span class="vterm-title">${(challenge.title||'Lab Terminal').replace(/</g,'&lt;')}</span>
        <button class="vterm-reset-btn icon-btn" title="Reset environment">↺ RESET</button>
      </div>
      <div class="vterm-output" role="log" aria-live="polite"></div>
      <div class="vterm-input-row">
        <span class="vterm-prompt-label" aria-hidden="true"></span>
        <input class="vterm-input" type="text" autocomplete="off" autocorrect="off"
               autocapitalize="off" spellcheck="false" aria-label="Terminal input"
               placeholder="type a command and press Enter">
      </div>
    </div>
    <style>
      .vterm{background:#050508;border:1px solid var(--border,#2a2a3a);font-family:var(--mono,'JetBrains Mono',Consolas,monospace);font-size:13px;line-height:1.6}
      .vterm-topbar{display:flex;align-items:center;gap:6px;padding:7px 12px;background:#0c0c14;border-bottom:1px solid var(--border,#2a2a3a)}
      .vterm-dot{width:11px;height:11px;border-radius:50%}
      .vterm-dot-red{background:#ff3b30}.vterm-dot-amber{background:#ffb000}.vterm-dot-green{background:#00ff88}
      .vterm-title{flex:1;text-align:center;font-size:11px;color:#556070;text-transform:uppercase;letter-spacing:.12em}
      .vterm-reset-btn{font-size:10px;margin-left:auto;color:#556070;border-color:#2a2a3a!important}
      .vterm-output{height:400px;overflow-y:auto;padding:12px 16px;white-space:pre-wrap;word-break:break-all;color:#b8ffd8}
      .vterm-input-row{display:flex;align-items:center;gap:6px;border-top:1px solid var(--border,#2a2a3a);padding:6px 10px;background:#080810}
      .vterm-prompt-label{color:#00ff88;white-space:nowrap;font-weight:700;font-size:12px}
      .vterm-input{flex:1;border:0;outline:0;background:transparent;color:#00ff88;font:inherit;font-size:13px;caret-color:#00ff88}
      .term-line{margin:0;padding:1px 0}
      .term-prompt{color:#00ff88;font-weight:700}
      .term-dir{color:#00d4ff}.term-file{color:#e0e0e0}.term-suid{color:#ff00ff;font-weight:700}
      .term-err{color:#ff3366}.term-info{color:#ffb000}.term-success{color:#00ff88;font-weight:700}
      .term-hint{color:#ffb000;border-left:3px solid #ffb000;padding-left:8px}
      .term-banner{color:#00ff88;font-weight:700}
      .term-help{color:#aeb6c5}.term-output{color:#b8ffd8}
    </style>
  `;

  const outputEl = container.querySelector('.vterm-output');
  const inputEl  = container.querySelector('.vterm-input');
  const promptEl = container.querySelector('.vterm-prompt-label');
  const resetBtn = container.querySelector('.vterm-reset-btn');

  const engine = new CTFTerminalEngine({ outputEl, inputEl, promptEl, challenge, onSolve });

  resetBtn?.addEventListener('click', () => engine.reset());

  /* Auto-focus on click anywhere in terminal */
  container.querySelector('.vterm')?.addEventListener('click', () => inputEl?.focus());

  return engine;
}
