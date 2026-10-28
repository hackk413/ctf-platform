/**
 * CTF Atlas — DOM Simulation & Interaction Test Suite
 * Fully simulates the browser environment in Node.js, runs portalJs,
 * and tests every user interaction for Admin and Cadet roles.
 */

import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { portalHtml, portalCss, portalJs } from '../lib/assets.mjs';

const ROOT = process.cwd();
const liveIntel = JSON.parse(fs.readFileSync(path.join(ROOT, 'data/live-intel.json'), 'utf8'));

// Minimal DOM Element Mock
class MockElement {
  constructor(tagName = 'div', id = '', className = '') {
    this.tagName = tagName.toUpperCase();
    this.id = id;
    this.className = className;
    this.classList = new MockClassList(this);
    this.children = [];
    this.parentNode = null;
    this.dataset = {};
    this.style = {};
    this._innerHTML = '';
    this._textContent = '';
    this.value = '';
    this.listeners = {};
    this.attributes = {};
  }

  get innerHTML() {
    return this._innerHTML;
  }

  set innerHTML(val) {
    this._innerHTML = String(val);
    // Simple HTML parsing to populate queryable children and dataset attributes
    this.children = [];
    this._parseChildMarkup(this._innerHTML);
  }

  get textContent() {
    return this._textContent || this._innerHTML.replace(/<[^>]*>/g, '');
  }

  set textContent(val) {
    this._textContent = String(val);
    this._innerHTML = String(val);
  }

  setAttribute(k, v) {
    this.attributes[k] = String(v);
    if (k === 'id') this.id = v;
    if (k === 'class') this.className = v;
    if (k.startsWith('data-')) {
      const camel = k.slice(5).replace(/-([a-z])/g, (_, g) => g.toUpperCase());
      this.dataset[camel] = v;
    }
  }

  getAttribute(k) {
    return this.attributes[k] ?? null;
  }

  removeAttribute(k) {
    delete this.attributes[k];
  }

  appendChild(child) {
    child.parentNode = this;
    this.children.push(child);
    return child;
  }

  remove() {
    if (this.parentNode) {
      const idx = this.parentNode.children.indexOf(this);
      if (idx !== -1) this.parentNode.children.splice(idx, 1);
      this.parentNode = null;
    }
  }

  focus() {}

  contains(node) {
    let cur = node;
    while (cur) {
      if (cur === this) return true;
      cur = cur.parentNode;
    }
    return false;
  }

  addEventListener(type, fn) {
    if (!this.listeners[type]) this.listeners[type] = [];
    this.listeners[type].push(fn);
  }

  dispatchEvent(event) {
    event.target = this;
    const fns = this.listeners[event.type] || [];
    for (const fn of fns) {
      fn(event);
      if (event._isStopped && event._isStopped()) return;
    }
    if (event.bubbles && this.parentNode && !(event._isStopped && event._isStopped())) {
      this.parentNode.dispatchEvent(event);
    }
  }

  click() {
    let stopped = false;
    const ev = {
      type: 'click',
      target: this,
      bubbles: true,
      preventDefault: () => {},
      stopPropagation: () => { stopped = true; },
      _isStopped: () => stopped
    };
    this.dispatchEvent(ev);
  }

  closest(selector) {
    let cur = this;
    while (cur) {
      if (cur.matches(selector)) return cur;
      cur = cur.parentNode;
    }
    return null;
  }

  matches(selector) {
    if (selector.includes(',')) {
      return selector.split(',').some(s => this.matches(s.trim()));
    }
    // Handle compound selector like .nav-item[data-view] or button.nav-item
    let s = selector;
    // Check tag
    const tagMatch = s.match(/^[a-zA-Z0-9\-]+/);
    if (tagMatch) {
      if (this.tagName.toLowerCase() !== tagMatch[0].toLowerCase()) return false;
      s = s.slice(tagMatch[0].length);
    }
    // Check classes
    const classMatches = s.match(/\.([a-zA-Z0-9\-_]+)/g);
    if (classMatches) {
      for (const cm of classMatches) {
        if (!this.classList.contains(cm.slice(1))) return false;
        s = s.replace(cm, '');
      }
    }
    // Check attributes
    const attrMatches = s.match(/\[([a-zA-Z0-9\-_]+)(?:="([^"]*)")?\]/g);
    if (attrMatches) {
      for (const am of attrMatches) {
        const m = am.match(/\[([a-zA-Z0-9\-_]+)(?:="([^"]*)")?\]/);
        const attrName = m[1];
        const attrVal = m[2];
        if (attrName.startsWith('data-')) {
          const key = attrName.slice(5).replace(/-([a-z])/g, (_, g) => g.toUpperCase());
          if (this.dataset[key] === undefined) return false;
          if (attrVal !== undefined && this.dataset[key] !== attrVal) return false;
        } else {
          const v = this.getAttribute(attrName);
          if (v === null) return false;
          if (attrVal !== undefined && v !== attrVal) return false;
        }
        s = s.replace(am, '');
      }
    }
    // Check id
    const idMatch = s.match(/#([a-zA-Z0-9\-_]+)/);
    if (idMatch) {
      if (this.id !== idMatch[1]) return false;
    }
    return true;
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] || null;
  }

  querySelectorAll(selector) {
    const parts = selector.trim().split(/\s+/);
    if (parts.length > 1) {
      let currentSet = [this];
      for (const part of parts) {
        const nextSet = [];
        for (const el of currentSet) {
          nextSet.push(...el._findDirectDescendants(part));
        }
        currentSet = nextSet;
      }
      return currentSet;
    }
    return this._findDirectDescendants(selector);
  }

  _findDirectDescendants(selector) {
    const matches = [];
    function search(el) {
      for (const child of el.children) {
        if (child.matches(selector)) matches.push(child);
        search(child);
      }
    }
    search(this);
    return matches;
  }

  _parseChildMarkup(html) {
    const tagRegex = /<([a-zA-Z0-9\-]+)([^>]*)>(.*?)<\/\1>|<([a-zA-Z0-9\-]+)([^>]*)\/?>/gs;
    let match;
    while ((match = tagRegex.exec(html)) !== null) {
      const tag = match[1] || match[4];
      const attrsStr = match[2] || match[5] || '';
      const content = match[3] || '';
      const child = new MockElement(tag);

      // parse attrs
      const attrRegex = /([a-zA-Z0-9\-]+)(?:=(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
      let am;
      while ((am = attrRegex.exec(attrsStr)) !== null) {
        const name = am[1];
        const val = am[2] ?? am[3] ?? am[4] ?? '';
        child.setAttribute(name, val);
      }
      child.parentNode = this;
      if (content) {
        child.innerHTML = content;
      }
      this.children.push(child);
    }
  }
}

class MockClassList {
  constructor(el) {
    this.el = el;
  }

  _getClasses() {
    return (this.el.className || '').split(/\s+/).filter(Boolean);
  }

  add(...classes) {
    const cur = new Set(this._getClasses());
    classes.forEach(c => cur.add(c));
    this.el.className = Array.from(cur).join(' ');
  }

  remove(...classes) {
    const cur = new Set(this._getClasses());
    classes.forEach(c => cur.delete(c));
    this.el.className = Array.from(cur).join(' ');
  }

  toggle(c, force) {
    const cur = new Set(this._getClasses());
    const has = cur.has(c);
    if (force !== undefined) {
      if (force) cur.add(c);
      else cur.delete(c);
    } else {
      if (has) cur.delete(c);
      else cur.add(c);
    }
    this.el.className = Array.from(cur).join(' ');
  }

  contains(c) {
    return this._getClasses().includes(c);
  }
}

function createDOMFromHtml(html) {
  const root = new MockElement('html');
  const body = new MockElement('body');
  const docEl = root;
  root.appendChild(body);

  // Parse root body elements from portalHtml
  const bodyContentMatch = html.match(/<body[^>]*>(.*?)<\/body>/s);
  if (bodyContentMatch) {
    body.innerHTML = bodyContentMatch[1];
  } else {
    body.innerHTML = html;
  }

  const doc = {
    documentElement: docEl,
    body: body,
    getElementById(id) {
      return root.querySelector('#' + id);
    },
    querySelector(sel) {
      return root.querySelector(sel);
    },
    querySelectorAll(sel) {
      return root.querySelectorAll(sel);
    },
    createElement(tag) {
      return new MockElement(tag);
    },
    addEventListener: (type, fn) => root.addEventListener(type, fn),
    dispatchEvent: (ev) => root.dispatchEvent(ev)
  };

  return { root, body, doc };
}

function runSessionTest(role, uid) {
  console.log(`\n======================================================`);
  console.log(`[TEST SESSION] Role: ${role.toUpperCase()} (uid: ${uid})`);
  console.log(`======================================================`);

  const { root, body, doc } = createDOMFromHtml(portalHtml);

  const alerts = [];
  const storage = {};

  const sandbox = {
    window: null,
    document: doc,
    navigator: {
      clipboard: {
        writeText: async (t) => t
      }
    },
    localStorage: {
      getItem: (k) => storage[k] ?? null,
      setItem: (k, v) => { storage[k] = String(v); },
      removeItem: (k) => { delete storage[k]; }
    },
    fetch: async (url) => {
      if (url.includes('/api/updates') || url.includes('live-intel.json')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ ok: true, data: liveIntel })
        };
      }
      return { ok: true, status: 200, json: async () => ({}) };
    },
    alert: (msg) => { alerts.push(msg); },
    addEventListener: (type, fn) => {},
    removeEventListener: () => {},
    innerWidth: 1024,
    innerHeight: 768,
    scrollTo: () => {},
    setTimeout: (fn, ms) => setTimeout(fn, ms),
    clearTimeout: (id) => clearTimeout(id),
    TextEncoder,
    TextDecoder,
    btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
    atob: (s) => Buffer.from(s, 'base64').toString('binary'),
    crypto: {
      subtle: {
        digest: async (algo, data) => new Uint8Array(32)
      }
    },
    ATLAS_USER: { uid, role }
  };
  sandbox.window = sandbox;

  const ctx = vm.createContext(sandbox);

  // 1. Evaluate portalJs
  try {
    vm.runInContext(portalJs, ctx);
    console.log(`  [PASS] portalJs evaluated with ZERO syntax or initial parse errors.`);
  } catch (err) {
    console.error(`  [FAIL] Evaluation threw:`, err);
    throw err;
  }

  // 2. Trigger DOMContentLoaded / boot
  try {
    doc.dispatchEvent({ type: 'DOMContentLoaded', bubbles: true });
    console.log(`  [PASS] DOMContentLoaded boot completed cleanly.`);
  } catch (err) {
    console.error(`  [FAIL] Boot failed:`, err);
    throw err;
  }

  const isCadet = role === 'cadet';

  // 3. Verify Nav Items
  const navItems = doc.querySelectorAll('.main-nav .nav-item');
  const expectedCount = isCadet ? 12 : 15;
  console.log(`  [PASS] Found ${navItems.length} nav items in main-nav (expected ${expectedCount}).`);
  assert.strictEqual(navItems.length, expectedCount);

  const views = navItems.map(b => b.dataset.view);
  if (isCadet) {
    assert(!views.includes('tools'), 'Cadet menu must NOT contain tools');
    assert(!views.includes('playbook'), 'Cadet menu must NOT contain playbook');
    assert(!views.includes('advisories'), 'Cadet menu must NOT contain advisories');
    console.log(`  [PASS] Restricted tools, playbook, and advisories are completely absent from Cadet menu.`);
  } else {
    assert(views.includes('tools'), 'Admin menu must contain tools');
    assert(views.includes('playbook'), 'Admin menu must contain playbook');
    assert(views.includes('advisories'), 'Admin menu must contain advisories');
    console.log(`  [PASS] Admin menu contains all tools, playbook, and advisories views.`);
  }

  // 4. Test Theme Toggle
  const themeBtn = doc.getElementById('themeToggle');
  assert(themeBtn, 'themeToggle button must exist');
  const initialTheme = sandbox.state.theme;
  themeBtn.click();
  const nextTheme = sandbox.state.theme;
  assert.notStrictEqual(initialTheme, nextTheme);
  console.log(`  [PASS] Theme toggle works: ${initialTheme} -> ${nextTheme}`);
  themeBtn.click(); // toggle back

  // 5. Test Menu Toggle
  const menuBtn = doc.getElementById('menuToggle');
  const appShell = doc.querySelector('.app-shell');
  const sidebar = doc.getElementById('sidebar');
  const backdrop = doc.getElementById('sidebarBackdrop');
  const mobileClose = doc.getElementById('mobileClose');

  assert(menuBtn, 'menuToggle button must exist');
  assert(appShell, 'app-shell must exist');
  assert(sidebar, 'sidebar must exist');
  assert(backdrop, 'sidebarBackdrop must exist');

  // Desktop toggle test (width > 820)
  sandbox.innerWidth = 1200;
  const initiallyCollapsed = appShell.classList.contains('sidebar-collapsed');
  menuBtn.click();
  const nowCollapsed = appShell.classList.contains('sidebar-collapsed');
  assert.notStrictEqual(initiallyCollapsed, nowCollapsed, 'Clicking menu toggle on desktop must toggle sidebar-collapsed');
  assert(sidebar.classList.contains('collapsed'), 'Sidebar element must also have .collapsed class');
  console.log(`  [PASS] Desktop menu toggle toggles .sidebar-collapsed (${initiallyCollapsed} -> ${nowCollapsed}).`);
  menuBtn.click(); // toggle back open
  assert(!appShell.classList.contains('sidebar-collapsed'), 'Desktop menu re-opened cleanly');

  // Mobile drawer toggle test (width <= 820)
  sandbox.innerWidth = 390; // mobile phone width
  assert(!sidebar.classList.contains('open'), 'Sidebar must start closed on mobile');
  menuBtn.click();
  assert(sidebar.classList.contains('open'), 'Sidebar must have .open on mobile after menuToggle click');
  assert(backdrop.classList.contains('active'), 'Backdrop must have .active on mobile after menuToggle click');
  console.log(`  [PASS] Mobile menu toggle opens drawer (.open) and activates backdrop (.active).`);

  // Clicking a nav item on mobile closes drawer
  const sampleNavItem = navItems[0];
  sampleNavItem.click();
  assert(!sidebar.classList.contains('open'), 'Sidebar drawer must close when a nav item is clicked on mobile');
  assert(!backdrop.classList.contains('active'), 'Backdrop must deactivate when a nav item is clicked on mobile');
  console.log(`  [PASS] Nav item click on mobile switches view and closes drawer cleanly.`);

  // Test mobile close button
  menuBtn.click();
  assert(sidebar.classList.contains('open'));
  if (mobileClose) {
    mobileClose.click();
    assert(!sidebar.classList.contains('open'), 'Mobile close button must close drawer');
    console.log(`  [PASS] Mobile close button [X] closes drawer.`);
  }

  // Test backdrop click closes drawer
  menuBtn.click();
  assert(sidebar.classList.contains('open'));
  backdrop.click();
  assert(!sidebar.classList.contains('open'), 'Backdrop click must close drawer');
  console.log(`  [PASS] Backdrop click closes mobile drawer.`);

  // 6. Test View Navigation
  const viewEl = doc.getElementById('view');
  assert(viewEl, '#view element must exist');

  for (const btn of navItems) {
    const v = btn.dataset.view;
    btn.click();
    assert.strictEqual(sandbox.state.view, v, `State view must be ${v}`);
    assert(viewEl.innerHTML.length > 50, `View ${v} rendered substantial HTML`);
  }
  console.log(`  [PASS] All ${navItems.length} nav buttons successfully render their corresponding views.`);

  // 7. Security / Permission Infiltration Test for Cadet
  if (isCadet) {
    alerts.length = 0;
    sandbox.setView('tools');
    assert(alerts.includes('This field is under development.'), 'Unauthorized tools view access must alert development');
    assert.notStrictEqual(sandbox.state.view, 'tools', 'Unauthorized view change must be blocked');

    alerts.length = 0;
    sandbox.setView('playbook');
    assert(alerts.includes('This field is under development.'), 'Unauthorized playbook view access must alert development');
    assert.notStrictEqual(sandbox.state.view, 'playbook', 'Unauthorized view change must be blocked');

    alerts.length = 0;
    sandbox.setView('advisories');
    assert(alerts.includes('This field is under development.'), 'Unauthorized advisories view access must alert development');
    assert.notStrictEqual(sandbox.state.view, 'advisories', 'Unauthorized view change must be blocked');

    alerts.length = 0;
    sandbox.openDomain('reverse');
    assert(alerts.includes('This field is under development.'), 'Unauthorized domain reverse must alert development');

    alerts.length = 0;
    sandbox.openDomain('pwn');
    assert(alerts.includes('This field is under development.'), 'Unauthorized domain pwn must alert development');

    alerts.length = 0;
    sandbox.openTextbookModal('reverse-ghidra');
    assert(alerts.includes('This field is under development.'), 'Unauthorized textbook reverse-ghidra must alert development');

    console.log(`  [PASS] Cadet security assertions passed: all restricted entry points strictly blocked with development alert.`);
  }

  console.log(`  [SUCCESS] All checks passed for ${role.toUpperCase()} profile!`);
}

async function main() {
  console.log('======================================================');
  console.log('CTF ATLAS // COMPREHENSIVE DOM & RUNTIME INTERACTION');
  console.log('======================================================');
  runSessionTest('admin', 'admin');
  runSessionTest('cadet', 'cadet');
  console.log('\n======================================================');
  console.log('ALL DOM INTERACTIONS & SECURITY ENFORCEMENTS VERIFIED!');
  console.log('======================================================');
}

main();
