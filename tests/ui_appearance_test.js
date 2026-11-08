#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const html = fs.readFileSync('web/index.html', 'utf8');
const matches = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
assert.equal(matches.length, 1, 'expected one embedded UI script');
const script = matches[0][1];
new vm.Script(script, { filename: 'web/index.html:inline-script' });

assert.match(html, /<option value="custom">Gambar khusus<\/option>/, 'custom mode is selectable');
assert.match(html, /id="languageSelect"[\s\S]*?<option value="id">Bahasa Indonesia<\/option>[\s\S]*?<option value="en">English<\/option>/, 'Indonesian and English can be selected in Settings');
assert.match(script, /xray-panel-language/, 'language choice is persisted in the browser');
assert.match(script, /document\.documentElement\.lang=language/, 'document language follows the selected language');
assert.match(html, /id="customBackgroundFile" type="file" accept="image\/png,image\/jpeg,image\/webp"/, 'file picker restricts image formats');
assert.match(html, /id="applyCustomBackground"[^>]*>Terapkan<\/button>/, 'apply action is present');
assert.match(html, /id="resetCustomBackground"[^>]*>Reset<\/button>/, 'reset action is present');
assert.match(html, /id="chooseCustomBackground"[^>]*tabindex="0"[^>]*role="button"/, 'file picker is keyboard-focusable');
assert.match(html, /fetch\('\/api\/background'/, 'custom image is loaded from authenticated server endpoint');
assert.match(script, /fetch\('\/api\/background',\{method:'PUT'/, 'custom image is uploaded to server');
assert.match(script, /api\('\/api\/background',null,'DELETE'\)/, 'custom image can be deleted server-side');
assert.match(html, /diselaraskan ke perangkat lain/, 'appearance is described as shared across devices');
assert.match(html, /background-size:cover/, 'background fills the page');
assert.match(html, /position:fixed;top:0;left:0;width:100vw;height:100vh/, 'background is fixed to the viewport instead of scroll content');
assert.match(html, /@supports\(height:100lvh\)\{#backdrop\{height:100lvh\}\}/, 'mobile background uses a stable large viewport height');
assert.match(html, /rgba\(255,255,255,\.62\)/, 'custom glass surface stays visibly transparent');
assert.match(html, /backdrop-filter:blur\(16px\) saturate\(145%\)/, 'custom mode uses visible liquid-glass styling');
assert.match(html, /id="addProfileButton"/, 'page-level add profile action is present');
assert.match(html, /id="addInboundDialog"/, 'top-level add profile opens a dialog with the existing form');
assert.doesNotMatch(html, /id="addInboundPanel"|id="refreshButton"/, 'lower add accordion and page-level refresh control are removed');
assert.match(script, /action:'reloadInbound',id:item\.id/, 'each inbound card can request a profile reload');
assert.match(script, /semua koneksi klien pada seluruh profil aktif dapat terputus sesaat/i, 'reload confirmation warns that the shared Xray daemon can interrupt all active profiles');
assert.ok(script.includes("if(!confirm(tr('Pemulihan akan menimpa pengguna, profil, gambar latar, dan pengaturan saat ini. Lanjutkan?')))return;"), 'backup restore confirmation follows the selected language');
assert.ok(script.includes("if(!confirm(tr('Perbarui Xray? Layanan dapat terputus sesaat.')))return;"), 'Xray update confirmation follows the selected language');
assert.ok(script.includes('"Hapus":"Delete"'), 'delete action has an English translation');
assert.ok(script.includes("del.textContent=tr('Hapus')"), 'user delete button follows the selected language');
assert.ok(script.includes("element('button','danger',tr('Hapus'))"), 'inbound delete button follows the selected language');
assert.match(html, /id="newUserInbound" required/, 'new-user profile selection is mandatory');
assert.match(script, /action:'addUser',name,inboundId/, 'new user request sends its selected profile');
assert.match(html, /© 2026 Gerald Zovka[\s\S]*?Repositori proyek/, 'footer uses a repository credit when no LICENSE file exists');
assert.doesNotMatch(html, /Panel lokal untuk mengelola konektivitas server/, 'old footer text is removed');
assert.doesNotMatch(script, /addEventListener\(['"]scroll/, 'background scaling is not changed by a scroll listener');

const compactStyle = html.match(/<style id="compact-ui">([\s\S]*?)<\/style>/)?.[1];
assert.ok(compactStyle, 'compact layout overrides are present');
assert.match(compactStyle, /#app\.wrap\{width:min\(980px,100%\);margin:0 auto;padding:14px 16px 18px\}/, 'main layout uses a narrower, compact canvas');
assert.match(compactStyle, /#app \.top-subtitle\{display:none\}/, 'decorative header subtitle is removed to simplify the header');
assert.match(compactStyle, /#app \.tabs\{position:sticky;/, 'compact navigation stays reachable while scrolling');
assert.match(compactStyle, /@media\(max-width:480px\)[\s\S]*?#app \.profile-actions\{display:grid;/, 'profile actions use a compact phone layout');
assert.match(compactStyle, /#app \.profile-actions\{display:grid;grid-template-columns:repeat\(4,minmax\(0,1fr\)\);gap:5px\}/, 'all four inbound actions stay in one compact row on mobile');
assert.match(compactStyle, /#app \.profile-actions button\{flex:initial;min-width:0;min-height:40px;height:40px;padding:4px 3px;font-size:10\.5px;line-height:1\.1;white-space:nowrap;overflow:hidden\}/, 'mobile action buttons are short, single-line, and remain tappable');
assert.match(compactStyle, /body\[data-background="custom"\] #app \.top,body\[data-background="custom"\] #app \.file-picker\{background-color:var\(--glass\)[^}]*backdrop-filter:blur\(16px\) saturate\(145%\)/, 'custom backgrounds keep liquid-glass header and picker surfaces');
assert.match(compactStyle, /#app \.custom-preview\{height:88px/, 'custom background preview is compact');
assert.match(script, /action:'mldsa65'/, 'per-inbound ML-DSA control remains available');
assert.match(script, /element\('button','secondary',tr\('Muat ulang'\)\)/, 'reload button keeps its concise bilingual label');
assert.match(script, /element\('button','secondary',tr\('ML-DSA'\)\)/, 'ML-DSA button uses a short visible label');
assert.match(script, /pqToggle\.title=pqActionLabel;pqToggle\.setAttribute\('aria-label',pqActionLabel\)/, 'ML-DSA button exposes a bilingual action title and accessible name');
assert.ok(script.includes('"Muat ulang":"Refresh"'), 'reload label translates into English');
assert.ok(script.includes('"Aktifkan ML-DSA-65":"Enable ML-DSA-65"') && script.includes('"Matikan ML-DSA-65":"Disable ML-DSA-65"'), 'ML-DSA action name translates into English');

const validatorLine = script.match(/^async function validateBackgroundFile\(file\)\{[^\n]*\}$/m)?.[0];
assert.ok(validatorLine, 'image validator is present');
let dimensions = [1920, 1080];
  const validate = vm.runInNewContext(`${validatorLine}; validateBackgroundFile`, {
    imageDimensions: async () => dimensions,
    tr: (text) => text,
  });
(async () => {
  const accepted = { type: 'image/webp', size: 1024 };
  assert.equal(await validate(accepted), accepted, 'valid WebP is accepted');
  await assert.rejects(validate({ type: 'image/svg+xml', size: 1024 }), /PNG, JPEG, atau WebP/);
  await assert.rejects(validate({ type: 'image/png', size: 5 * 1024 * 1024 + 1 }), /5 MB/);
  await assert.rejects(validate({ type: 'image/jpeg', size: 0 }), /1 byte/);
  dimensions = [9000, 6000];
  await assert.rejects(validate({ type: 'image/png', size: 1024 }), /40 megapiksel/);
  dimensions = [12001, 1];
  await assert.rejects(validate({ type: 'image/png', size: 1024 }), /12.000 px/);
  console.log('UI appearance tests passed (syntax, shared background API, glass styling, lifecycle controls, profile assignment, and file validation).');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
