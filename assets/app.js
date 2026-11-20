/* Veille Sécu — agrégateur d'alertes de sécurité à partir de flux RSS */
(() => {
  'use strict';

  // ------- Configuration -------
  const DEFAULT_FEEDS = [
    { id: 'alertes', label: 'Alertes', source: 'CERT-FR', url: 'https://cert.cyber.gouv.fr/alerte/feed/' },
    { id: 'menaces', label: 'Menaces', source: 'CERT-FR', url: 'https://cert.cyber.gouv.fr/cti/feed/' },
    { id: 'securite', label: 'Sécurité', source: 'CERT-FR', url: 'https://cert.cyber.gouv.fr/avis/feed/' },
    { id: 'itconnect', label: 'IT-Connect', source: 'IT-Connect', url: 'https://www.it-connect.fr/feed/' },
  ];
  // Proxys CORS publics utilisés pour le rafraîchissement « en direct » depuis le navigateur.
  const PROXIES = [
    u => `https://api.allorigins.win/raw?url=${encodeURIComponent(u)}`,
    u => `https://corsproxy.io/?url=${encodeURIComponent(u)}`,
    u => `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(u)}`,
  ];
  const STALE_MS = 2 * 3600e3;
  const COLORS = { all: 'var(--c-all)', alertes: 'var(--c-alertes)', menaces: 'var(--c-menaces)', securite: 'var(--c-securite)', itconnect: 'var(--c-itconnect)' };

  // ------- Stockage local -------
  const store = {
    get(k, d) { try { const v = localStorage.getItem('vs:' + k); return v === null ? d : JSON.parse(v); } catch { return d; } },
    set(k, v) { try { localStorage.setItem('vs:' + k, JSON.stringify(v)); } catch {} },
  };
  const readSet = new Set(store.get('read', []));
  const starSet = new Set(store.get('starred', []));
  const prevVisit = store.get('lastVisit', Date.now() - 24 * 3600e3);
  store.set('lastVisit', Date.now());
  const persistSets = () => {
    store.set('read', [...readSet].slice(-3000));
    store.set('starred', [...starSet]);
  };

  // ------- État -------
  const state = {
    feeds: DEFAULT_FEEDS,
    items: new Map(),
    sessionNew: new Set(),
    filter: { cat: store.get('cat', 'all'), period: 0, q: '', unread: false, starred: false },
    generatedAt: null,
    mode: 'cache',
    loading: false,
    notif: store.get('notif', false),
  };

  // ------- Utilitaires -------
  const $ = s => document.querySelector(s);
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const norm = s => String(s ?? '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
  const highlight = (text, q) => {
    const safe = esc(text);
    if (!q) return safe;
    const words = q.split(/\s+/).filter(w => w.length > 1).map(w => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
    return words.length ? safe.replace(new RegExp(`(${words.join('|')})`, 'gi'), '<mark>$1</mark>') : safe;
  };
  const rtf = new Intl.RelativeTimeFormat('fr', { numeric: 'auto' });
  const ago = iso => {
    if (!iso) return '';
    const s = (new Date(iso) - Date.now()) / 1000;
    const units = [['year', 31536000], ['month', 2592000], ['week', 604800], ['day', 86400], ['hour', 3600], ['minute', 60]];
    for (const [u, sec] of units) if (Math.abs(s) >= sec) return rtf.format(Math.round(s / sec), u);
    return "à l'instant";
  };
  const fullDate = iso => iso ? new Date(iso).toLocaleString('fr-FR', { dateStyle: 'full', timeStyle: 'short' }) : '';
  const feedById = id => state.feeds.find(f => f.id === id) || { label: id, source: '' };
  const isNew = it => state.sessionNew.has(it.id) || (it.date && new Date(it.date).getTime() > prevVisit && !readSet.has(it.id));

  // ------- Analyse RSS côté navigateur -------
  function parseFeedXml(xml, feed) {
    const doc = new DOMParser().parseFromString(xml, 'text/xml');
    if (doc.querySelector('parsererror')) throw new Error('XML invalide');
    const nodes = [...doc.querySelectorAll('item')].length ? [...doc.querySelectorAll('item')] : [...doc.querySelectorAll('entry')];
    const txt = (n, sel) => { const e = n.getElementsByTagName(sel)[0]; return e ? e.textContent.trim() : ''; };
    const strip = html => { const d = new DOMParser().parseFromString(html || '', 'text/html'); return (d.body.textContent || '').replace(/\s+/g, ' ').trim(); };
    return nodes.slice(0, 60).map(n => {
      const title = strip(txt(n, 'title'));
      let link = txt(n, 'link');
      if (!link) { const l = n.getElementsByTagName('link')[0]; link = l ? l.getAttribute('href') || '' : ''; }
      const content = txt(n, 'content:encoded');
      const summary = strip(txt(n, 'description') || txt(n, 'summary') || content).slice(0, 600);
      const d = new Date(txt(n, 'pubDate') || txt(n, 'updated') || txt(n, 'published') || txt(n, 'dc:date'));
      const cves = [...new Set(`${title} ${strip(content)} ${summary}`.match(/CVE-\d{4}-\d{4,7}/gi) || [])].map(c => c.toUpperCase()).slice(0, 12);
      return {
        id: txt(n, 'guid') || txt(n, 'id') || link || title, feed: feed.id, source: feed.source, title, link,
        date: isNaN(d) ? null : d.toISOString(), summary,
        categories: [...n.getElementsByTagName('category')].map(c => c.textContent.trim()).slice(0, 8), cves,
      };
    }).filter(i => i.title);
  }

  async function fetchWithTimeout(url, ms = 12000) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), ms);
    try {
      const r = await fetch(url, { signal: ctrl.signal, cache: 'no-store' });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return await r.text();
    } finally { clearTimeout(t); }
  }

  async function fetchLive(feed) {
    let lastErr;
    for (const p of PROXIES) {
      try {
        const xml = await fetchWithTimeout(p(feed.url));
        if (!/<(rss|feed|rdf)/i.test(xml)) throw new Error('Réponse inattendue');
        return parseFeedXml(xml, feed);
      } catch (e) { lastErr = e; }
    }
    throw lastErr;
  }

  // ------- Chargement des données -------
  function merge(list) {
    const fresh = [];
    for (const it of list) {
      if (!it || !it.id) continue;
      if (!state.items.has(it.id)) fresh.push(it);
      state.items.set(it.id, { ...state.items.get(it.id), ...it });
    }
    return fresh;
  }

  async function loadConfig() {
    try {
      const r = await fetch('config/feeds.json', { cache: 'no-store' });
      if (r.ok) state.feeds = await r.json();
    } catch {}
  }

  async function loadSnapshot() {
    try {
      const r = await fetch(`data/feeds.json?t=${Date.now()}`, { cache: 'no-store' });
      if (!r.ok) throw 0;
      const data = await r.json();
      if (data.generatedAt) state.generatedAt = data.generatedAt;
      return merge(data.items || []);
    } catch { return []; }
  }

  async function loadLive() {
    const results = await Promise.allSettled(state.feeds.map(fetchLive));
    let ok = 0; const fresh = [];
    results.forEach(r => { if (r.status === 'fulfilled') { ok++; fresh.push(...merge(r.value)); } });
    if (ok) { state.mode = 'live'; state.generatedAt = new Date().toISOString(); }
    return { ok, total: state.feeds.length, fresh };
  }

  async function refresh({ initial = false, forceLive = false } = {}) {
    if (state.loading) return;
    state.loading = true;
    setStatus('loading');
    $('#refreshBtn').classList.add('spin');
    const knownBefore = state.items.size;

    let fresh = await loadSnapshot();
    if (initial) render();

    const stale = !state.generatedAt || Date.now() - new Date(state.generatedAt) > STALE_MS;
    let live = null;
    if (forceLive || stale || state.items.size === 0) {
      live = await loadLive();
      fresh = fresh.concat(live.fresh);
    }

    state.loading = false;
    $('#refreshBtn').classList.remove('spin');

    if (!state.items.size) {
      showNotice('Impossible de récupérer les flux pour le moment. Le fichier <code>data/feeds.json</code> est vide et les proxys CORS ne répondent pas. Lancez la GitHub Action « Mise à jour des flux RSS » ou <code>node scripts/fetch-feeds.mjs</code>.');
      setStatus('err');
    } else {
      showNotice(live && live.ok < live.total && state.mode !== 'live' ? `Rafraîchissement direct indisponible (${live.total - live.ok}/${live.total} flux) — affichage des données en cache.` : null);
      setStatus(stale && (!live || !live.ok) ? 'off' : 'ok');
    }

    if (!initial && knownBefore > 0 && fresh.length) announce(fresh);
    render();
  }

  // ------- Annonces de nouveaux articles -------
  function announce(fresh) {
    fresh.forEach(i => state.sessionNew.add(i.id));
    const byFeed = {};
    fresh.forEach(i => (byFeed[i.feed] ||= []).push(i));
    for (const [fid, list] of Object.entries(byFeed)) {
      const f = feedById(fid);
      toast(`${list.length} nouvel${list.length > 1 ? 'les' : 'le'} publication${list.length > 1 ? 's' : ''} · ${f.label}`, list[0].title, COLORS[fid]);
    }
    if (state.notif && 'Notification' in window && Notification.permission === 'granted') {
      const top = fresh.find(i => i.feed === 'alertes') || fresh[0];
      const n = new Notification(`🛡️ ${feedById(top.feed).label} — ${fresh.length} nouveauté${fresh.length > 1 ? 's' : ''}`, { body: top.title, tag: 'veille-secu' });
      n.onclick = () => { window.focus(); if (top.link) window.open(top.link, '_blank', 'noopener'); };
    }
    updateTitle();
  }

  function toast(title, body, color = 'var(--accent)') {
    const el = document.createElement('div');
    el.className = 'toast';
    el.style.borderLeftColor = color;
    el.innerHTML = `<strong>${esc(title)}</strong>${esc(body || '')}`;
    $('#toasts').appendChild(el);
    setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 300); }, 6000);
  }

  function showNotice(html) {
    const n = $('#notice');
    n.hidden = !html;
    if (html) n.innerHTML = html;
  }

  function setStatus(kind) {
    const dot = $('#liveDot');
    dot.className = 'pulse ' + (kind === 'ok' ? '' : kind);
    const label = $('#lastUpdate');
    if (kind === 'loading') { label.textContent = 'Actualisation…'; return; }
    if (!state.generatedAt) { label.textContent = 'Aucune donnée'; return; }
    label.textContent = `Mis à jour ${ago(state.generatedAt)} · ${state.mode === 'live' ? 'en direct' : 'instantané'}`;
    label.title = fullDate(state.generatedAt);
  }

  // ------- Filtrage & rendu -------
  function filtered() {
    const { cat, period, q, unread, starred } = state.filter;
    const nq = norm(q).trim();
    const terms = nq.split(/\s+/).filter(Boolean);
    const since = period ? Date.now() - period * 86400e3 : 0;
    return [...state.items.values()]
      .filter(i => cat === 'all' || i.feed === cat)
      .filter(i => !since || (i.date && new Date(i.date).getTime() >= since))
      .filter(i => !unread || !readSet.has(i.id))
      .filter(i => !starred || starSet.has(i.id))
      .filter(i => {
        if (!terms.length) return true;
        const hay = norm(`${i.title} ${i.summary} ${(i.cves || []).join(' ')} ${(i.categories || []).join(' ')}`);
        return terms.every(t => hay.includes(t));
      })
      .sort((a, b) => (b.date || '').localeCompare(a.date || ''));
  }

  function renderStats() {
    const all = [...state.items.values()];
    const day = Date.now() - 86400e3;
    const cats = [{ id: 'all', label: 'Toutes' }, ...state.feeds];
    $('#stats').innerHTML = cats.map(c => {
      const list = c.id === 'all' ? all : all.filter(i => i.feed === c.id);
      const unread = list.filter(i => !readSet.has(i.id)).length;
      const today = list.filter(i => i.date && new Date(i.date) > day).length;
      const days = Array.from({ length: 14 }, (_, k) => {
        const start = new Date(); start.setHours(0, 0, 0, 0); start.setDate(start.getDate() - (13 - k));
        const end = start.getTime() + 86400e3;
        return list.filter(i => i.date && +new Date(i.date) >= +start && +new Date(i.date) < end).length;
      });
      const max = Math.max(1, ...days);
      return `<button class="stat ${state.filter.cat === c.id ? 'active' : ''}" data-cat="${c.id}" style="--c:${COLORS[c.id] || 'var(--accent)'}">
        <div class="stat-label"><i></i>${esc(c.label)}</div>
        <div class="stat-value">${list.length}</div>
        <div class="stat-sub"><b>${today}</b> dernières 24 h · ${unread} non lu${unread > 1 ? 's' : ''}</div>
        <div class="spark" title="Publications sur 14 jours">${days.map(d => `<span style="height:${(d / max) * 100}%"></span>`).join('')}</div>
      </button>`;
    }).join('');
  }

  function renderTabs() {
    const cats = [{ id: 'all', label: 'Tout' }, ...state.feeds];
    $('#tabs').innerHTML = cats.map((c, idx) => {
      const n = [...state.items.values()].filter(i => (c.id === 'all' || i.feed === c.id) && isNew(i)).length;
      return `<button class="tab ${state.filter.cat === c.id ? 'active' : ''}" role="tab" aria-selected="${state.filter.cat === c.id}" data-cat="${c.id}" style="--c:${COLORS[c.id] || 'var(--accent)'}" title="Raccourci : ${idx + 1}">
        ${esc(c.label)}<span class="count">${n || ''}</span></button>`;
    }).join('');
  }

  function renderFeed() {
    const list = filtered();
    const feed = $('#feed');
    const tpl = $('#cardTpl');
    const q = state.filter.q.trim();
    feed.innerHTML = '';
    $('#empty').hidden = !!list.length || state.loading || !state.items.size;

    if (!state.items.size && state.loading) {
      feed.innerHTML = Array.from({ length: 6 }, () => '<div class="skeleton"></div>').join('');
      return;
    }

    const frag = document.createDocumentFragment();
    list.slice(0, 300).forEach((it, idx) => {
      const node = tpl.content.firstElementChild.cloneNode(true);
      const f = feedById(it.feed);
      node.style.setProperty('--c', COLORS[it.feed] || 'var(--accent)');
      node.style.animationDelay = `${Math.min(idx, 12) * 30}ms`;
      node.dataset.id = it.id;
      node.classList.toggle('is-read', readSet.has(it.id));
      node.classList.toggle('is-new', isNew(it));
      node.querySelector('.cat').textContent = `${f.label}${f.source && f.source !== f.label ? ' · ' + f.source : ''}`;
      const time = node.querySelector('.date');
      time.textContent = ago(it.date);
      time.dateTime = it.date || '';
      time.title = fullDate(it.date);
      const a = node.querySelector('.card-title a');
      a.href = it.link || '#';
      a.innerHTML = highlight(it.title, q);
      node.querySelector('.card-summary').innerHTML = highlight(it.summary || '', q);
      node.querySelector('.cves').innerHTML = (it.cves || []).map(c =>
        `<a class="cve" href="https://nvd.nist.gov/vuln/detail/${esc(c)}" target="_blank" rel="noopener" title="Voir sur NVD">${highlight(c, q)}</a>`).join('');
      node.querySelector('.open').href = it.link || '#';
      const star = node.querySelector('.star');
      star.textContent = starSet.has(it.id) ? '★' : '☆';
      star.classList.toggle('on', starSet.has(it.id));
      node.querySelector('.read').textContent = readSet.has(it.id) ? 'Marquer non lu' : 'Marquer lu';
      if ((it.summary || '').length < 180) node.querySelector('.more').remove();
      frag.appendChild(node);
    });
    feed.appendChild(frag);
  }

  function updateTitle() {
    const n = [...state.items.values()].filter(isNew).length;
    document.title = (n ? `(${n}) ` : '') + 'Veille Sécu — Alertes de sécurité';
  }

  function render() {
    renderStats();
    renderTabs();
    renderFeed();
    updateTitle();
    $('#unreadOnly').classList.toggle('active', state.filter.unread);
    $('#starredOnly').classList.toggle('active', state.filter.starred);
    $('#notifBtn').classList.toggle('active', state.notif);
  }

  // ------- Interactions -------
  function setCat(cat) {
    state.filter.cat = cat;
    store.set('cat', cat);
    render();
  }

  function markRead(id, value = true) {
    value ? readSet.add(id) : readSet.delete(id);
    state.sessionNew.delete(id);
    persistSets();
  }

  document.addEventListener('click', e => {
    const catBtn = e.target.closest('[data-cat]');
    if (catBtn) return setCat(catBtn.dataset.cat);

    const period = e.target.closest('[data-period]');
    if (period) {
      document.querySelectorAll('[data-period]').forEach(b => b.classList.toggle('active', b === period));
      state.filter.period = +period.dataset.period;
      return renderFeed();
    }

    const card = e.target.closest('.card');
    if (!card) return;
    const id = card.dataset.id;
    if (e.target.closest('.star')) {
      starSet.has(id) ? starSet.delete(id) : starSet.add(id);
      persistSets(); render();
    } else if (e.target.closest('.read')) {
      markRead(id, !readSet.has(id)); render();
    } else if (e.target.closest('.more')) {
      card.classList.toggle('expanded');
      e.target.textContent = card.classList.contains('expanded') ? 'Réduire' : 'Détails';
    } else if (e.target.closest('.open, .card-title a')) {
      markRead(id, true);
      setTimeout(render, 150);
    }
  });

  let searchTimer;
  $('#search').addEventListener('input', e => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { state.filter.q = e.target.value; renderFeed(); }, 120);
  });
  $('#unreadOnly').addEventListener('click', () => { state.filter.unread = !state.filter.unread; render(); });
  $('#starredOnly').addEventListener('click', () => { state.filter.starred = !state.filter.starred; render(); });
  $('#markAllRead').addEventListener('click', () => {
    filtered().forEach(i => { readSet.add(i.id); state.sessionNew.delete(i.id); });
    persistSets(); render();
    toast('C’est à jour', 'Tous les articles affichés ont été marqués comme lus.');
  });
  $('#refreshBtn').addEventListener('click', () => refresh({ forceLive: true }));

  // Thème
  const applyTheme = t => { document.documentElement.dataset.theme = t; store.set('theme', t); };
  applyTheme(store.get('theme', matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'));
  $('#themeBtn').addEventListener('click', () => applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));

  // Notifications
  $('#notifBtn').addEventListener('click', async () => {
    if (!('Notification' in window)) return toast('Non supporté', 'Votre navigateur ne gère pas les notifications.');
    if (state.notif) { state.notif = false; store.set('notif', false); render(); return toast('Notifications désactivées', ''); }
    const perm = Notification.permission === 'granted' ? 'granted' : await Notification.requestPermission();
    if (perm !== 'granted') return toast('Permission refusée', 'Autorisez les notifications dans les réglages du navigateur.');
    state.notif = true; store.set('notif', true); render();
    toast('Notifications activées', 'Vous serez prévenu·e des nouvelles alertes tant que la page est ouverte.');
  });

  // Rafraîchissement automatique
  let autoTimer;
  const auto = $('#autoRefresh');
  auto.value = String(store.get('auto', 15));
  const setupAuto = () => {
    clearInterval(autoTimer);
    store.set('auto', +auto.value);
    if (+auto.value) autoTimer = setInterval(() => refresh({ forceLive: true }), +auto.value * 60e3);
  };
  auto.addEventListener('change', setupAuto);

  // Mise à jour régulière des dates relatives
  setInterval(() => { setStatus(state.loading ? 'loading' : $('#liveDot').classList.contains('off') ? 'off' : 'ok'); document.querySelectorAll('.card time').forEach(t => { t.textContent = ago(t.dateTime); }); }, 60e3);

  // Raccourcis clavier
  document.addEventListener('keydown', e => {
    if (e.target.matches('input, select, textarea') || e.metaKey || e.ctrlKey || e.altKey) {
      if (e.key === 'Escape' && e.target.id === 'search') { e.target.value = ''; state.filter.q = ''; e.target.blur(); renderFeed(); }
      return;
    }
    if (e.key === '/') { e.preventDefault(); $('#search').focus(); }
    else if (e.key.toLowerCase() === 'r') refresh({ forceLive: true });
    else if (/^[1-9]$/.test(e.key)) {
      const cats = ['all', ...state.feeds.map(f => f.id)];
      if (cats[+e.key - 1]) setCat(cats[+e.key - 1]);
    }
  });

  // Démarrage
  (async () => {
    state.loading = true; renderFeed(); state.loading = false;
    await loadConfig();
    if (!['all', ...state.feeds.map(f => f.id)].includes(state.filter.cat)) state.filter.cat = 'all';
    await refresh({ initial: true });
    setupAuto();
  })();
})();
