#!/usr/bin/env node
// Récupère les flux RSS configurés et génère data/feeds.json (Node 18+, sans dépendance).
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { notifyNew } from './notify.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const feeds = JSON.parse(await readFile(resolve(root, 'config/feeds.json'), 'utf8'));
const outFile = resolve(root, 'data/feeds.json');
const MAX_PER_FEED = 60;

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', hellip: '…', rsquo: '’', lsquo: '‘', ldquo: '“', rdquo: '”', laquo: '«', raquo: '»', ndash: '–', mdash: '—', eacute: 'é', egrave: 'è', agrave: 'à', ccedil: 'ç', ecirc: 'ê' };
export const decode = (s = '') => s
  .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
  .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(+d))
  .replace(/&([a-z]+);/gi, (m, n) => ENTITIES[n.toLowerCase()] ?? m);
const unCdata = (s = '') => s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1');
const stripHtml = (s = '') => decode(s.replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim();
const tag = (xml, name) => { const m = xml.match(new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)</${name}>`, 'i')); return m ? unCdata(m[1]).trim() : ''; };
const tags = (xml, name) => [...xml.matchAll(new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)</${name}>`, 'gi'))].map(m => decode(unCdata(m[1]).trim()));

export function parseRss(xml, feed) {
  const blocks = xml.match(/<item[\s>][\s\S]*?<\/item>/gi) || xml.match(/<entry[\s>][\s\S]*?<\/entry>/gi) || [];
  return blocks.slice(0, MAX_PER_FEED).map(b => {
    const title = stripHtml(tag(b, 'title'));
    let link = decode(tag(b, 'link'));
    if (!link) { const m = b.match(/<link[^>]*href="([^"]+)"/i); link = m ? decode(m[1]) : ''; }
    const date = tag(b, 'pubDate') || tag(b, 'updated') || tag(b, 'published') || tag(b, 'dc:date');
    const raw = tag(b, 'description') || tag(b, 'summary') || tag(b, 'content:encoded') || tag(b, 'content');
    const summary = stripHtml(raw).slice(0, 600);
    const cves = [...new Set((`${title} ${stripHtml(tag(b, 'content:encoded'))} ${summary}`).match(/CVE-\d{4}-\d{4,7}/gi) || [])].map(c => c.toUpperCase()).slice(0, 12);
    const d = new Date(date);
    return {
      id: decode(tag(b, 'guid') || tag(b, 'id')) || link || title,
      feed: feed.id, source: feed.source, title, link,
      date: isNaN(d) ? null : d.toISOString(),
      summary, categories: tags(b, 'category').slice(0, 8), cves,
    };
  }).filter(i => i.title);
}

async function fetchFeed(feed) {
  const res = await fetch(feed.url, { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; VeilleSecuRSS/1.0)', Accept: 'application/rss+xml, application/xml, text/xml, */*' }, signal: AbortSignal.timeout(30000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return parseRss(await res.text(), feed);
}

async function main() {
  let previous = { items: [] };
  try { previous = JSON.parse(await readFile(outFile, 'utf8')); } catch {}
  const status = {};
  const items = [];
  for (const feed of feeds) {
    try {
      const got = await fetchFeed(feed);
      items.push(...got);
      status[feed.id] = { ok: true, count: got.length };
      console.log(`✔ ${feed.label}: ${got.length} articles`);
    } catch (e) {
      // En cas d'échec, on conserve les articles précédents de ce flux.
      const kept = (previous.items || []).filter(i => i.feed === feed.id);
      items.push(...kept);
      status[feed.id] = { ok: false, error: String(e.message || e), count: kept.length };
      console.warn(`✘ ${feed.label}: ${e.message} (conservés : ${kept.length})`);
    }
  }
  items.sort((a, b) => (b.date || '').localeCompare(a.date || ''));
  // N'écrit le fichier que si le contenu a changé (évite un commit et un déploiement à chaque vérification).
  const same = JSON.stringify({ feeds, status, items }) === JSON.stringify({ feeds: previous.feeds, status: previous.status, items: previous.items });
  if (same) {
    console.log(`→ Aucun changement (${items.length} articles).`);
  } else {
    await mkdir(dirname(outFile), { recursive: true });
    await writeFile(outFile, JSON.stringify({ generatedAt: new Date().toISOString(), feeds, status, items }, null, 2) + '\n');
    console.log(`→ ${items.length} articles écrits dans data/feeds.json`);
  }
  await notifyNew({ items, previousItems: previous.items || [], feeds });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main().catch(e => { console.error(e); process.exit(1); });
