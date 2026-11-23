# Auditor di Race Condition nell'Aggiornamento di WordPress & RCE | TAVARDT Italia

> Audit di Resilienza Aziendale contro le Vulnerabilità di Race Condition durante gli Aggiornamenti WordPress, l'Esposizione delle Cartelle Transitorie e l'Esecuzione di Codice da Remoto (RCE)

[![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-Active-brightgreen)](https://tavardt-italia.github.io/wordpress-upgrade-race-checker-it/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security: CIS WordPress](https://img.shields.io/badge/Security-CIS%20WordPress%20%7C%20OWASP-red.svg)](https://owasp.org/)

## Panoramica della Vulnerabilità e Architettura Difensiva

Il processo standard di aggiornamento dei componenti in WordPress (core, temi e plugin) gestito da `class-wp-upgrader.php` scarica gli archivi compressi in formato ZIP e li estrae nella directory transitoria `wp-content/upgrade/` tramite la funzione `unzip_file()`.

Durante l'intervallo di tempo tra l'estrazione dei file su disco e lo spostamento atomico nelle directory finali, si apre una finestra critica di concorrenza (Race Condition) nella radice pubblica web. Se il server web non dispone di regole rigorose di restrizione perimetrale o di filtraggio WAF, qualsiasi richiesta esterna anonima può accedere direttamente ai file estratti in `wp-content/upgrade/`. Se l'interprete PHP (FastCGI/PHP-FPM) autorizza l'elaborazione di script in questa cartella, gli aggressori possono eseguire codice malevolo arbitrario (Remote Code Execution) con i privilegi dell'utente web.

Questo repository mette a disposizione uno strumento web interattivo di diagnosi perimetrale e un'utility CLI in Python senza dipendenze esterne per audit automatizzati.

## Applicazione Web Interattiva

Accedi alla versione interattiva ospitata su GitHub Pages:
[https://tavardt-italia.github.io/wordpress-upgrade-race-checker-it/](https://tavardt-italia.github.io/wordpress-upgrade-race-checker-it/)

Funzionalità dell'applicazione web:
* Verifica in tempo reale della connettività e misurazione della latenza di rete.
* Rilevamento dell'esposizione della directory transitoria `wp-content/upgrade/` e dell'elenco dei file.
* Matrice comparativa di architettura (Topologia vulnerabile vs Server protetto).
* Générateur automatisé de configurations défensives pour Nginx, Apache (.htaccess), wp-config.php et Cloudflare WAF.
* Interface réactive conçue pour terminaux mobiles et ordinateurs de bureau.

## Utilisation du Scanner CLI en Python

Le script `wordpress_upgrade_checker.py` ne requiert aucune bibliothèque tierce et fonctionne sous tout environnement Python 3.8+ :

```bash
# Lancer un audit direct sur un domaine
python wordpress_upgrade_checker.py https://site-entreprise.fr

# Lancer un audit au format JSON pour les pipelines CI/CD et DevSecOps
python wordpress_upgrade_checker.py https://site-entreprise.fr --json

# Afficher les blocs de configuration pour la remédiation et le durcissement
python wordpress_upgrade_checker.py --remediate
```

## Contrôles Architecturaux et Mesures de Durcissement

Pour neutraliser définitivement la surface d'attaque liée aux conditions de concurrence et au RCE sous WordPress, appliquez une stratégie de défense en profondeur sur 4 niveaux :

1. **Isolation des File Temporaires (wp-config.php) :**
   Configurez la constante `WP_TEMP_DIR` pour pointer vers un cartella externe hors de la radice publique `DocumentRoot` :
   ```php
   define('WP_TEMP_DIR', dirname(__DIR__) . '/tmp/');
   define('DISALLOW_FILE_MODS', true);
   define('DISALLOW_FILE_EDIT', true);
   ```

2. **Blocage Perimetrale sous Nginx (nginx.conf) :**
   Rejetez les requêtes HTTP ciblant le cartella d'upgrade et interdisez la compilation des scripts `.php` dans les directorys de contenu :
   ```nginx
   location ~* /wp-content/upgrade/ {
       deny all;
       return 403;
   }
   location ~* ^/wp-content/(uploads|upgrade)/.*\.php$ {
       deny all;
       return 403;
   }
   ```

3. **Protection sous Apache (.htaccess) :**
   Définissez des règles strictes dans `wp-content/upgrade/.htaccess` :
   ```apache
   <FilesMatch "\.(php|phtml|php[0-9]|sh|cgi)$">
       Require all denied
   </FilesMatch>
   Options -Indexes
   ```

4. **Règle Personnalisée Cloudflare WAF :**
   Créez une règle de blocage rejetant toute requête contenant `(http.request.uri.path contains "/wp-content/upgrade/")`.

## Portails Officiels

* **Portale Aziendale TAVARDT Italia :** [https://ag.tavardt.com/it/](https://ag.tavardt.com/it/)
* **Servizi di Cybersicurezza :** [https://ag.tavardt.com/it/cybersicurezza/](https://ag.tavardt.com/it/cybersicurezza/)
* **Hub di Strumenti Difensivi :** [https://tools.tavardt.com/it/](https://tools.tavardt.com/it/)
* **Organisation GitHub :** [https://github.com/TAVARDT-Italia](https://github.com/TAVARDT-Italia)

## Licenza

Distribué sous licence MIT. Consultez le fichier `LICENSE` pour plus de précisions.
