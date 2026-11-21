# 🛡️ Veille Sécu — Flux RSS sécurité

Tableau de bord moderne et interactif pour suivre les nouvelles alertes de sécurité, alimenté par des flux RSS :

| Catégorie  | Source     | Flux |
|------------|------------|------|
| Alertes    | CERT-FR    | https://cert.cyber.gouv.fr/alerte/feed/ |
| Menaces    | CERT-FR    | https://cert.cyber.gouv.fr/cti/feed/ |
| Sécurité   | CERT-FR    | https://cert.cyber.gouv.fr/avis/feed/ |
| IT-Connect | IT-Connect | https://www.it-connect.fr/feed/ |

## Fonctionnalités

- Onglets et cartes statistiques par catégorie (compteurs, activité sur 14 jours)
- Badges **Nouveau** depuis votre dernière visite, compteur dans l'onglet du navigateur
- Recherche instantanée (titre, résumé, CVE) avec surlignage
- Filtres : 24 h / 7 j / 30 j, non lus, favoris
- Détection des **CVE** avec lien direct vers la NVD
- Lu / non lu, favoris (mémorisés dans le navigateur)
- Actualisation automatique (5, 15, 30 min), **notifications du navigateur** et toasts pour les nouvelles publications
- Thème sombre / clair, responsive, raccourcis clavier (`/`, `R`, `1`–`5`)

## Fonctionnement

Un navigateur ne peut pas lire directement ces flux (restriction CORS). Le site combine donc deux sources :

1. **`data/feeds.json`** — généré par `scripts/fetch-feeds.mjs` (Node 18+, sans dépendance) et
   mis à jour **toutes les 30 minutes** par la GitHub Action `.github/workflows/update-feeds.yml`.
2. **Mode direct** — au clic sur « Actualiser » ou pendant l'actualisation automatique, le navigateur
   interroge aussi les flux via des proxys CORS publics pour récupérer les toutes dernières publications.

## Notifications sur téléphone (ntfy)

À chaque passage de la tâche GitHub (toutes les 30 min), une notification [ntfy](https://ntfy.sh) est envoyée
pour chaque nouvel article. Les notifications sont regroupées au-delà de 3 nouveautés dans une même catégorie.

| Catégorie  | Notification | Priorité |
|------------|--------------|----------|
| Alertes    | 🚨 Alerte CERT-FR — « Une nouvelle alerte a été publiée. » | urgente |
| Menaces    | 🕵️ Menace CERT-FR — « Une nouvelle menace a été publiée. » | haute |
| Sécurité   | 🛡️ Avis de sécurité CERT-FR — « Un nouvel avis de sécurité a été publié. » | normale |
| IT-Connect | 📰 IT-Connect — « Un nouvel article a été publié. » | normale |

Chaque notification contient le titre, un résumé, les CVE et un bouton « Lire l'article ».
Textes, emojis et priorités se modifient dans `config/feeds.json` (bloc `notify`).

**Mise en place**

1. Installez l'application **ntfy** (Play Store / App Store), appuyez sur **+** et abonnez-vous à un sujet
   au nom long et difficile à deviner (ex. `veille-secu-k7p2x9q4m`). Toute personne connaissant ce nom peut lire les notifications.
2. Sur GitHub : *Settings → Secrets and variables → Actions → New repository secret*,
   nom `NTFY_TOPIC`, valeur : le nom du sujet.
3. *(Optionnel)* onglet *Variables* : `SITE_URL` = l'adresse du site, pour ajouter un bouton « Voir le site ».
4. Test : *Actions → Mise à jour des flux RSS → Run workflow*, cochez « Envoyer une notification de test ».

Options avancées : `NTFY_SERVER` (variable, serveur ntfy auto-hébergé) et `NTFY_TOKEN` (secret, sujet protégé).

## Vérification toutes les 5 minutes (cron-job.org)

Les tâches planifiées de GitHub sont peu fiables : en pratique elles ne tournent parfois que toutes les ~6 heures.
Pour une vérification régulière, un service externe gratuit déclenche la tâche :

1. GitHub → photo de profil → *Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token*.
   Dépôt : uniquement `Flux-RSS-Securit-` ; permission **Actions : Read and write** ; expiration au choix. Copiez le jeton.
2. Sur [cron-job.org](https://cron-job.org), créez un compte puis un *cronjob* :
   - URL : `https://api.github.com/repos/FRENSKYT/Flux-RSS-Securit-/actions/workflows/update-feeds.yml/dispatches`
   - Planification : toutes les 5 minutes
   - *Advanced* → méthode **POST**, en-têtes `Authorization: Bearer <jeton>` et `Accept: application/vnd.github+json`,
     corps `{"ref":"main"}`
3. Un appel réussi renvoie le code **204**.

Le fichier `data/feeds.json` n'est commité que lorsqu'il change, pour ne pas multiplier les commits.

## Mise en ligne (GitHub Pages)

1. Fusionnez cette branche dans la branche par défaut (les tâches planifiées GitHub ne tournent que sur celle-ci).
2. *Settings → Pages* : source « Deploy from a branch », branche par défaut, dossier `/ (root)`.
3. *Settings → Actions → General → Workflow permissions* : cochez « Read and write permissions ».
4. *Actions → Mise à jour des flux RSS → Run workflow* pour générer les premières données.

## En local

```bash
node scripts/fetch-feeds.mjs
```

```bash
python3 -m http.server 8000
```

Puis ouvrez http://localhost:8000.

## Ajouter un flux

Ajoutez une entrée dans `config/feeds.json` (`id`, `label`, `source`, `url`). Pour lui donner une couleur,
ajoutez `--c-<id>` dans `assets/style.css` et l'entrée correspondante dans `COLORS` (`assets/app.js`).
