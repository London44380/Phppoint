# PhpPoint — scanner de découverte d'endpoints PHP

Trouve les endpoints PHP d'un site à partir de deux sources indépendantes : un crawl same-host (HTML, JS inline/externe, `robots.txt`, `sitemap.xml`) qui extrait toute URL ou action de formulaire PHP-ish, et une wordlist de noms de fichiers PHP courants (extensions configurables pour les piles historiques), sondée avec une détection de faux-404 pour ne pas remonter de faux positifs sur les sites catch-all/SPA. Repère aussi les chemins à nom sensible (sauvegarde, config, admin) et les paramètres de requête suspects (LFI/SSRF/injection de commande), et dédoublonne les endpoints au contenu identique.
*Finds a site's PHP endpoints from a same-host crawl plus a wordlist probe with soft-404 baseline detection, flags backup/config/admin-sounding paths and suspicious query parameters, and dedupes byte-identical endpoints.*

Compagnon de [PHPVerse](https://forgejo.london.li/London088/Phpverse).

> **Usage autorisé uniquement.** Ne scanner que des hôtes que vous possédez ou pour lesquels vous avez une autorisation écrite. La découverte est heuristique : à vérifier manuellement avant d'agir.

## Usage
```bash
python3 phppoint.py exemple.com
python3 phppoint.py https://exemple.com -f cibles.txt
python3 phppoint.py exemple.com --extensions php,php3,phtml --json
```

## Options
| Option | Rôle |
|---|---|
| `targets` | Un ou plusieurs hôtes, IP ou URL |
| `-f`, `--file` | Fichier avec une cible par ligne (`#` pour les commentaires) |
| `-p`, `--ports` | Ports web à essayer, séparés par virgule (défaut `443,80`) |
| `-t`, `--timeout` | Timeout par requête (défaut 5 s) |
| `-w`, `--workers` | Sondes concurrentes par hôte (défaut 10) |
| `--max-pages` | Pages max explorées pendant le crawl (défaut 150) |
| `--no-crawl` | Ignore le crawl same-host, wordlist uniquement |
| `--no-wordlist` | Ignore la sonde par wordlist, crawl uniquement |
| `--extra-wordlist` | Fichier de mots supplémentaires à ajouter à la wordlist intégrée |
| `--extensions` | Extensions PHP-ish à sonder/reconnaître, séparées par virgule (défaut `php` ; ajouter `php3,php4,php5,php7,phtml` pour les piles historiques) |
| `--delay` | Pause en secondes avant chaque requête (throttle de politesse, défaut 0) |
| `-o`, `--output` | Écrit aussi le rapport dans ce fichier (combiner avec `--no-color` pour un fichier texte propre) |
| `--json` | Sortie JSON lisible par machine (sans bannière ni couleurs) |
| `--no-color` | Désactive les couleurs |

## Ce qu'il signale
| Signal | Exemple |
|---|---|
| Nom à motif de sauvegarde/éditeur | `config.php.bak`, `index.php~`, `wp-config.php.save` |
| Nom à consonance sensible | `config`, `setup`, `install`, `db`, `database`, `connect` |
| Surface admin/auth | `admin`, `login`, `wp-login` |
| Gestion de fichiers | `upload`, `file`, `import`, `export`, `backup`, `dump` |
| `xmlrpc.php` | Surface d'abus brute-force/pingback WordPress |
| Paramètres de requête | `file`/`page`/`template`/`include`/`doc` (LFI), `url`/`redirect`/`next` (SSRF/open redirect), `cmd`/`exec` (injection de commande) |
| Contenu identique | Signalé quand deux endpoints rendent le même corps (alias, routeur catch-all) |

Aucune dépendance externe (stdlib Python uniquement).
