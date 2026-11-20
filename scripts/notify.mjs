// Envoi des notifications ntfy (https://ntfy.sh) pour les nouveaux articles.
//
// Variables d'environnement :
//   NTFY_TOPIC   (obligatoire) nom du sujet ntfy — à garder secret
//   NTFY_SERVER  (optionnel)   serveur ntfy, https://ntfy.sh par défaut
//   NTFY_TOKEN   (optionnel)   jeton d'accès si le sujet est protégé
//   SITE_URL     (optionnel)   adresse du site, ajoute un bouton « Voir le site »

const MAX_DETAILED = 3;   // au-delà, les nouveautés d'un flux sont regroupées en une seule notification
const MAX_PER_RUN = 15;   // garde-fou anti-spam

const firstSentence = (s = '', max = 220) => {
  const t = s.replace(/\s+/g, ' ').trim();
  if (t.length <= max) return t;
  const cut = t.slice(0, max);
  const dot = cut.lastIndexOf('. ');
  return (dot > 80 ? cut.slice(0, dot + 1) : cut.replace(/\s+\S*$/, '') + '…');
};
const cleanTitle = t => t.replace(/\s*\(\d{1,2}\s+\S+\s+\d{4}\)\s*$/, ''); // retire « (18 novembre 2026) »
const fill = (tpl, n) => tpl.replace('{n}', n);

/** Construit les messages ntfy à partir des nouveaux articles, groupés par flux. */
export function buildMessages(newItems, feeds, { topic, siteUrl } = {}) {
  const messages = [];
  for (const feed of feeds) {
    const list = newItems.filter(i => i.feed === feed.id);
    if (!list.length) continue;
    const n = feed.notify || {};
    const title = n.title || feed.label;
    const base = { topic, title, priority: n.priority ?? 3, tags: n.tags || [] };
    const siteAction = siteUrl ? [{ action: 'view', label: 'Voir le site', url: siteUrl, clear: true }] : [];

    if (list.length <= MAX_DETAILED) {
      for (const it of list) {
        const lines = [n.one || `Nouvelle publication : ${feed.label}`, '', `« ${cleanTitle(it.title)} »`];
        const summary = firstSentence(it.summary);
        if (summary) lines.push('', summary);
        if (it.cves?.length) lines.push('', `🔎 ${it.cves.slice(0, 4).join(', ')}${it.cves.length > 4 ? ` +${it.cves.length - 4}` : ''}`);
        messages.push({
          ...base,
          message: lines.join('\n'),
          click: it.link || undefined,
          actions: [...(it.link ? [{ action: 'view', label: "Lire l'article", url: it.link, clear: true }] : []), ...siteAction],
        });
      }
    } else {
      const shown = list.slice(0, 6).map(i => `• ${cleanTitle(i.title)}`);
      if (list.length > 6) shown.push(`… et ${list.length - 6} autre(s)`);
      messages.push({
        ...base,
        message: [fill(n.many || `{n} nouvelles publications : ${feed.label}`, list.length), '', ...shown].join('\n'),
        click: siteUrl || list[0].link || undefined,
        actions: siteAction,
      });
    }
  }
  return messages.slice(0, MAX_PER_RUN);
}

/** Envoie les messages au serveur ntfy (publication JSON). */
export async function sendMessages(messages, { server = 'https://ntfy.sh', token } = {}) {
  let sent = 0;
  for (const msg of messages) {
    try {
      const res = await fetch(server.replace(/\/+$/, '') + '/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify(msg),
        signal: AbortSignal.timeout(15000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status} ${await res.text()}`);
      sent++;
    } catch (e) {
      console.warn(`✘ ntfy : échec de l'envoi « ${msg.title} » : ${e.message}`);
    }
  }
  return sent;
}

/**
 * Détermine les nouveautés et envoie les notifications.
 * Un flux sans historique (première exécution, flux ajouté) n'envoie rien, pour éviter une avalanche.
 */
export async function notifyNew({ items, previousItems, feeds, env = process.env }) {
  const topic = env.NTFY_TOPIC?.trim();
  if (!topic) { console.log('ℹ ntfy : NTFY_TOPIC non défini, aucune notification envoyée.'); return 0; }
  const opts = { topic, siteUrl: env.SITE_URL?.trim() || undefined };

  let fresh;
  if (env.NTFY_TEST === 'true') {
    // Notification de test : le dernier article de chaque flux.
    fresh = feeds.map(f => items.find(i => i.feed === f.id)).filter(Boolean);
    console.log('ℹ ntfy : mode test.');
  } else {
    const known = new Set(previousItems.map(i => i.id));
    const feedsWithHistory = new Set(previousItems.map(i => i.feed));
    fresh = items.filter(i => !known.has(i.id) && feedsWithHistory.has(i.feed));
  }
  if (!fresh.length) { console.log('ℹ ntfy : aucune nouveauté.'); return 0; }

  const messages = buildMessages(fresh, feeds, opts);
  const sent = await sendMessages(messages, { server: env.NTFY_SERVER?.trim() || undefined, token: env.NTFY_TOKEN?.trim() || undefined });
  console.log(`✔ ntfy : ${sent}/${messages.length} notification(s) envoyée(s) pour ${fresh.length} nouveauté(s).`);
  return sent;
}
