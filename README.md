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
