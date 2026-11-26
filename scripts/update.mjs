// Aggiorna docs/data.enc.json con i dati del Custom Report del portale partner,
// SENZA commissioni, saldo o ricavi. I dati vengono cifrati con REPORT_PASSWORD.
//
// Variabili d'ambiente:
//   ETORO_EMAIL, ETORO_PASSWORD  credenziali del portale (GitHub Secrets)
//   REPORT_PASSWORD              password della pagina per i sub-affiliati (GitHub Secret)
//   BACKFILL_MONTHS              mesi di storico da scaricare al primo avvio (default 12)
//   REFRESH_DAYS                 giorni recenti riscaricati a ogni giro (default 45)
//   MOCK_FILE                    solo per i test: legge le righe da un file invece del portale
//
// Regola d'oro: nei log non si stampano MAI valori dei dati (il repo è pubblico),
// solo nomi di colonne, conteggi e passaggi.

import { readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';

const PORTAL = 'https://por.etoro.com/en-gb/dashboard/custom-report';
const API = 'https://affapi.etoro.com/api/';
const OUT = new URL('../docs/data.enc.json', import.meta.url);

// Colonne ammesse nella pagina. Tutto ciò che non è qui viene scartato.
const ALLOW = [
  'date', 'month', 'campaign', 'countryId', 'bannerName', 'affiliateID',
  'registrations', 'ftd', 'ftde', 'ftdAmount', 'ftdeAmount', 'depositsAmount',
  'clicks', 'impressions', 'refundsAndChargebacks',
];
// Rete di sicurezza: anche se finissero nell'elenco sopra, questi campi non passano mai.
const DENY = /commission|cpa|revenue|percentage|payout|payment(?!.*eligible)|balance|earning|income|profit|bonus/i;

// Group: Date=1, Banner=2, Campaign(Serial ID)=4, CustomerId=8, Country=16, Month=64
// Select: base=4, Registrations=2, Revenues=8, Clicks=16, Refunds&Chargebacks=32
const GROUP = 1 + 4 + 16;
const SELECT = 4 + 2 + 16 + 32;

const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);
const need = (k) => {
  const v = process.env[k];
  if (!v) { console.error(`Manca la variabile ${k} (impostala nei Secrets del repository).`); process.exit(1); }
  return v;
};

// ---------- cifratura (compatibile con la pagina: PBKDF2-SHA256 + AES-GCM) ----------
const ITER = 600000;
const b64 = (u8) => Buffer.from(u8).toString('base64');
const unb64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));
async function deriveKey(password, salt, iter) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, base,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function encrypt(obj, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt, ITER);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(obj)));
  return { v: 1, kdf: 'PBKDF2-SHA256', iter: ITER, salt: b64(salt), iv: b64(iv), ct: b64(new Uint8Array(ct)) };
}
async function decrypt(box, password) {
  const key = await deriveKey(password, unb64(box.salt), box.iter);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(box.iv) }, key, unb64(box.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}

// ---------- utilità date ----------
const ymd = (d) => d.toISOString().slice(0, 10);
const usDate = (d) => `${d.getUTCMonth() + 1}/${d.getUTCDate()}/${d.getUTCFullYear()}`; // come il portale (en-US)
const addDays = (d, n) => { const x = new Date(d); x.setUTCDate(x.getUTCDate() + n); return x; };
function normDate(v) {
  if (v == null) return null;
  const s = String(v);
  let m = s.match(/^(\d{4})-(\d{2})-(\d{2})/); if (m) return `${m[1]}-${m[2]}-${m[3]}`;
  m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})/); if (m) return `${m[3]}-${m[1].padStart(2, '0')}-${m[2].padStart(2, '0')}`;
  const d = new Date(s); return isNaN(d) ? s : ymd(d);
}

// ---------- pulizia righe ----------
const seenDropped = new Set();
function clean(row, countries) {
  const out = {};
  for (const [k, v] of Object.entries(row)) {
    if (!ALLOW.includes(k) || DENY.test(k)) { seenDropped.add(k); continue; }
    out[k] = v;
  }
  if ('date' in out) out.date = normDate(out.date);
  if ('countryId' in out) { out.country = countries[out.countryId] || ''; delete out.countryId; }
  return out;
}
const rowKey = (r) => [r.date, r.campaign, r.country, r.bannerName, r.affiliateID].join('|');

// ---------- portale ----------
async function openPortal() {
  const { chromium } = await import('playwright');
  const browser = await chromium.launch();
  const context = await browser.newContext({ locale: 'en-GB', timezoneId: 'Europe/Rome' });
  const page = await context.newPage();
  let headers = null; let tier = null;
  page.on('request', (req) => {
    const u = new URL(req.url());
    if (u.hostname !== 'affapi.etoro.com') return;
    const h = req.headers();
    if (h.authorization && !headers) headers = h;
    if (/\/performance\/Aggregate/i.test(u.pathname) && u.searchParams.get('tier')) tier = u.searchParams.get('tier');
  });

  log('Apro il portale…');
  await page.goto(PORTAL, { waitUntil: 'domcontentloaded', timeout: 90000 });
  await page.waitForSelector('#logonIdentifier', { timeout: 90000 });
  log('Pagina di login caricata, inserisco le credenziali.');
  await page.fill('#logonIdentifier', need('ETORO_EMAIL'));
  await page.fill('#password', need('ETORO_PASSWORD'));
  await page.click('#next');

  // Login riuscito = si torna su por.etoro.com. Altrimenti mostro l'errore della pagina di login.
  const ok = await page.waitForURL((u) => u.hostname === 'por.etoro.com', { timeout: 60000 }).then(() => true).catch(() => false);
  if (!ok) {
    const err = await page.locator('.error.pageLevel, .error.itemLevel.show, #error').allInnerTexts().catch(() => []);
    const msg = err.map((s) => s.trim()).filter(Boolean).join(' / ');
    const mfa = await page.locator('input[type=tel], #verificationCode, #otpCode').count().catch(() => 0);
    await browser.close();
    if (mfa) throw new Error('Il portale chiede un codice di verifica (2FA): l\'accesso automatico non può proseguire.');
    throw new Error(`Login non riuscito. ${msg ? 'Messaggio del portale: ' + msg : 'Nessun messaggio visibile (possibile blocco o pagina cambiata).'}`);
  }
  log('Login riuscito.');

  if (!page.url().includes('custom-report')) await page.goto(PORTAL, { waitUntil: 'domcontentloaded', timeout: 90000 });
  // Aspetto che il portale faccia almeno una chiamata autenticata, poi provo a creare il report per leggere il tier.
  for (let i = 0; i < 60 && !headers; i++) await page.waitForTimeout(500);
  const btn = page.locator('.my-reports-create-report-btn, button:has-text("Create Report")').first();
  if (await btn.count().catch(() => 0)) {
    await btn.click().catch(() => {});
    for (let i = 0; i < 30 && !tier; i++) await page.waitForTimeout(500);
  }
  if (!headers) { await browser.close(); throw new Error('Login riuscito ma non trovo il token del portale (pagina cambiata?).'); }
  log(`Token acquisito. Tier del report: ${tier ?? 'non letto, uso 1'}.`);

  const pass = {};
  for (const [k, v] of Object.entries(headers)) if (!/^(host|content-length|cookie|:)/i.test(k)) pass[k] = v;
  const get = (path, params) => page.evaluate(async ({ url, hdrs }) => {
    const r = await fetch(url, { headers: hdrs, credentials: 'include' });
    const text = await r.text();
    return { status: r.status, text };
  }, { url: API + path + (params ? '?' + new URLSearchParams(params) : ''), hdrs: pass });

  return { browser, get, tier: tier ?? '1' };
}

async function fetchRange(portal, from, to, showAffiliate) {
  const params = { fromDate: usDate(from), toDate: usDate(to), tier: portal.tier, Group: String(GROUP), Select: String(SELECT), ShowAffiliateID: String(showAffiliate) };
  const r = await portal.get('v2/performance/Aggregate', params);
  if (r.status !== 200) throw new Error(`Aggregate ${ymd(from)}→${ymd(to)}: HTTP ${r.status}`);
  const data = JSON.parse(r.text || '[]');
  return Array.isArray(data) ? data : (data.items || data.data || []);
}

// ---------- main ----------
async function main() {
  const reportPassword = need('REPORT_PASSWORD');
  const backfillMonths = Number(process.env.BACKFILL_MONTHS || 12);
  const refreshDays = Number(process.env.REFRESH_DAYS || 45);

  let prev = null;
  if (existsSync(OUT)) {
    try { prev = await decrypt(JSON.parse(await readFile(OUT, 'utf8')), reportPassword); log(`Dati esistenti: ${prev.rows.length} righe.`); }
    catch { log('Non riesco a leggere i dati esistenti (password cambiata?): li ricreo da zero.'); }
  }

  const today = new Date(Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth(), new Date().getUTCDate()));
  const from = prev ? addDays(today, -refreshDays) : addDays(today, -Math.round(backfillMonths * 30.5));

  let raw = []; let countries = {};
  if (process.env.MOCK_FILE) {
    const mock = JSON.parse(await readFile(process.env.MOCK_FILE, 'utf8'));
    raw = mock.rows; countries = mock.countries || {};
    log(`MOCK: ${raw.length} righe lette da file.`);
  } else {
    const portal = await openPortal();
    try {
      const c = await portal.get('v1/countries');
      if (c.status === 200) for (const x of JSON.parse(c.text)) countries[x.id] = x.name;
      // Il portale limita gli intervalli: scarico a blocchi di 60 giorni.
      let showAffiliate = true;
      for (let a = from; a <= today; a = addDays(a, 60)) {
        const b = addDays(a, 59) < today ? addDays(a, 59) : today;
        let rows;
        try { rows = await fetchRange(portal, a, b, showAffiliate); }
        catch (e) {
          if (!showAffiliate) throw e;
          log(`Richiesta con dettaglio sub-affiliati non accettata (${e.message}), riprovo senza.`);
          showAffiliate = false; rows = await fetchRange(portal, a, b, false);
        }
        log(`Blocco ${ymd(a)} → ${ymd(b)}: ${rows.length} righe.`);
        raw.push(...rows);
      }
    } finally { await portal.browser.close(); }
  }

  if (raw.length) log('Colonne ricevute dal portale:', Object.keys(Object.assign({}, ...raw.slice(0, 50))).join(', '));
  const fresh = raw.map((r) => clean(r, countries));
  if (seenDropped.size) log('Colonne ESCLUSE dalla pagina:', [...seenDropped].join(', '));

  // Unione con lo storico: i giorni nella finestra appena scaricata vengono sostituiti.
  const fromStr = ymd(from);
  const kept = (prev?.rows || []).filter((r) => !r.date || r.date < fromStr);
  const map = new Map(kept.map((r) => [rowKey(r), r]));
  for (const r of fresh) map.set(rowKey(r), r);
  const rows = [...map.values()].sort((a, b) => String(a.date).localeCompare(String(b.date)));

  const same = prev && JSON.stringify(prev.rows) === JSON.stringify(rows);
  if (same) { log(`Nessuna novità (${rows.length} righe): non scrivo nulla.`); return; }

  const payload = { updatedAt: new Date().toISOString(), rows };
  await writeFile(OUT, JSON.stringify(await encrypt(payload, reportPassword)) + '\n');
  log(`Dati aggiornati e cifrati: ${rows.length} righe.`);
}

main().catch((e) => { console.error('ERRORE:', e.message); process.exit(1); });
