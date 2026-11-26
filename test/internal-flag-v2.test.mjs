// Local only, no network: runs the real internal-flag code from every page that
// has it (extracted from the HTML) against a fake browser (cookie jar +
// localStorage) and checks the v2 rules:
//  - ?ciq_internal=1 sets the cookie (1 year, Path=/, SameSite=Lax, Secure,
//    Domain=.clarityiq.ai on our hosts) AND the localStorage key
//  - ?ciq_internal=0 clears both
//  - either one alone counts, and the two heal each other
//  - when set, CIQ_SRC reports utm_source=internal / utm_medium=flag
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const pages = readdirSync(root).filter(f => f.endsWith('.html'))
  .filter(f => readFileSync(join(root, f), 'utf8').includes('const CIQ_INTERNAL = (function () {'));

function extract(html) {
  const a = html.indexOf("const CIQ_SRC_KEY = 'ciq_src';");
  const endMarker = ': CIQ_SRC_STATE.src;';
  const b = html.indexOf(endMarker, a) + endMarker.length;
  assert.ok(a > 0 && b > a, 'flag code found');
  return html.slice(a, b) + '\n;({ CIQ_INTERNAL, CIQ_SRC });';
}

// Minimal cookie jar honouring Max-Age=0 deletes and Domain/host-only keys.
function makeEnv({ url, store = {}, cookies = [], storageBroken = false }) {
  const u = new URL(url);
  const jar = new Map(); // key: name|domain-or-host -> {value, attrs}
  const writes = [];
  for (const c of cookies) jar.set(c.split('=')[0] + '|' + u.hostname, { value: c.split('=')[1], attrs: '' });
  const doc = {
    referrer: '',
    get cookie() { return [...jar.entries()].map(([k, v]) => k.split('|')[0] + '=' + v.value).join('; '); },
    set cookie(s) {
      writes.push(s);
      const parts = s.split(';').map(x => x.trim());
      const [name, value] = [parts[0].split('=')[0], parts[0].split('=').slice(1).join('=')];
      const attrs = Object.fromEntries(parts.slice(1).map(p => { const [k, ...v] = p.split('='); return [k.toLowerCase(), v.join('=') || true]; }));
      const dom = attrs.domain ? String(attrs.domain).replace(/^\./, '') : u.hostname;
      if (attrs.secure && u.protocol !== 'https:') return; // browsers drop these
      const key = name + '|' + dom;
      if (attrs['max-age'] === '0') jar.delete(key); else jar.set(key, { value, attrs });
    },
  };
  const data = new Map(Object.entries(store));
  const ls = { setItem: (k, v) => { if (storageBroken) throw new Error('blocked'); data.set(k, String(v)); },
    getItem: k => { if (storageBroken) throw new Error('blocked'); return data.has(k) ? data.get(k) : null; },
    removeItem: k => { if (storageBroken) throw new Error('blocked'); data.delete(k); } };
  const win = { localStorage: ls, sessionStorage: ls };
  const ctx = vm.createContext({ window: win, document: doc, location: { search: u.search, pathname: u.pathname, hostname: u.hostname, protocol: u.protocol },
    URLSearchParams, URL, Date, JSON, Object, String, RegExp, Error });
  return { ctx, jar, data, writes };
}
function run(html, opts) {
  const env = makeEnv(opts);
  const out = vm.runInContext(extract(html), env.ctx);
  return { ...env, internal: out.CIQ_INTERNAL, src: out.CIQ_SRC };
}

const targets = [...pages.map(f => ['site ' + f, join(root, f)])];

describe('internal flag v2 on every site page', () => {
  test('all 12 pages carry the new block', () => { assert.equal(pages.length, 12); });
  for (const [label, file] of targets) {
    const html = readFileSync(file, 'utf8');
    describe(label, () => {
      test('?ciq_internal=1 sets cookie + localStorage and tags internal', () => {
        const r = run(html, { url: 'https://clarityiq.ai/?ciq_internal=1' });
        assert.equal(r.internal, true);
        assert.equal(r.data.get('ciq_internal'), '1');
        assert.ok(r.jar.has('ciq_internal|clarityiq.ai'));
        const w = r.writes.find(s => s.startsWith('ciq_internal=1'));
        for (const part of ['Max-Age=31536000', 'Path=/', 'SameSite=Lax', 'Secure', 'Domain=.clarityiq.ai']) assert.ok(w.includes(part), part + ' in ' + w);
        assert.equal(r.src.utm_source, 'internal');
        assert.equal(r.src.utm_medium, 'flag');
      });
      test('?ciq_internal=0 clears both and untags', () => {
        const r = run(html, { url: 'https://clarityiq.ai/?ciq_internal=0', store: { ciq_internal: '1' }, cookies: ['ciq_internal=1'] });
        assert.equal(r.internal, false);
        assert.equal(r.data.has('ciq_internal'), false);
        assert.equal(r.jar.size, 0);
        assert.notEqual(r.src.utm_source, 'internal');
      });
      test('no flag at all stays untagged and writes no cookie', () => {
        const r = run(html, { url: 'https://clarityiq.ai/' });
        assert.equal(r.internal, false);
        assert.equal(r.writes.length, 0);
        assert.equal(r.src.utm_source, 'direct');
      });
      test('cookie alone counts and heals localStorage', () => {
        const r = run(html, { url: 'https://clarityiq.ai/which-lens-for-cataract-surgery.html', cookies: ['ciq_internal=1'] });
        assert.equal(r.internal, true);
        assert.equal(r.data.get('ciq_internal'), '1');
        assert.equal(r.src.utm_source, 'internal');
      });
      test('localStorage alone counts (old-link devices) and gains the cookie', () => {
        const r = run(html, { url: 'https://clarityiq.ai/', store: { ciq_internal: '1' } });
        assert.equal(r.internal, true);
        assert.ok(r.jar.has('ciq_internal|clarityiq.ai'));
        assert.equal(r.src.utm_source, 'internal');
      });
      test('blocked localStorage: the cookie still flags the device', () => {
        const r = run(html, { url: 'https://clarityiq.ai/?ciq_internal=1', storageBroken: true });
        assert.equal(r.internal, true);
        assert.equal(r.src.utm_source, 'internal');
      });
      test('app host reads the cookie set on the site (shared Domain)', () => {
        const r = run(html, { url: 'https://app.clarityiq.ai/', cookies: ['ciq_internal=1'] });
        assert.equal(r.internal, true);
      });
      test('http localhost drops Secure so local testing works, nothing else changes', () => {
        const r = run(html, { url: 'http://localhost:8080/?ciq_internal=1' });
        assert.equal(r.internal, true);
        assert.ok(!r.writes[0].includes('Secure'));
        assert.ok(!r.writes[0].includes('Domain='));
      });
      test('an explicit utm_source in the URL never beats the flag', () => {
        const r = run(html, { url: 'https://clarityiq.ai/?ciq_internal=1&utm_source=linkedin&utm_campaign=x' });
        assert.equal(r.src.utm_source, 'internal');
        assert.equal(r.src.utm_campaign, 'x');
      });
    });
  }
});
