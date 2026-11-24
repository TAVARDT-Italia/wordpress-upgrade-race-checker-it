# Centro di Hardening e Audit WordPress Upgrade Race Condition

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-italia.github.io/wordpress-upgrade-race-checker-it/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Vulnerability](https://img.shields.io/badge/Vulnerability-Race%20Condition-red.svg)](https://tavardt-italia.github.io/wordpress-upgrade-race-checker-it/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Repository ufficiale e riferimento tecnico per la mitigazione della vulnerabilità di **Race Condition nell'Aggiornamento WordPress ed Esecuzione di Codice da Remoto (RCE)**.

***

## 1. Panoramica della Vulnerabilità

Durante l'aggiornamento del core, dei temi o dei plugin, WordPress scarica ed estrae temporaneamente archivi ZIP nella cartella `wp-content/upgrade/` prima della verifica e del trasferimento definitivo.

Se il server web consente l'esecuzione di script PHP nelle sottodirectory di contenuto, un aggressore può richiamare direttamente i file appena decompressi durante la finestra di concorrenza, ottenendo l'Esecuzione di Codice da Remoto (RCE) con i permessi del processo web.

### Fattori di Rischio Principali:
* Cartella `wp-content/upgrade/` accessibile pubblicamente via HTTP
* Esecuzione FastCGI/PHP attiva nelle cartelle uploads e upgrade
* Assenza della direttiva `WP_TEMP_DIR` all'esterno della DocumentRoot

***

## 2. Audit Deterministico via CLI

Poiché i browser applicano restrizioni di sicurezza (CORS e sandbox) che impediscono verifiche dirette a livello di socket di rete, utilizza l'utility ufficiale in Python direttamente nel tuo terminale o pipeline CI/CD:

```bash
# 1. Scaricare l'utility ufficiale di audit
curl -sO https://raw.githubusercontent.com/TAVARDT-Italia/wordpress-upgrade-race-checker-it/main/audit_wp_race.py

# 2. Eseguire l'audit diretto contro il tuo dominio
python audit_wp_race.py https://tuo-dominio.it
```

### Parametri Supportati:
* Bersaglio come argomento posizionale o `-u https://tuo-dominio.it`
* `-t <secondi>` : Timeout in secondi (predefinito: 5)
* `-j` : Output strutturato in formato JSON per pipeline automatizzate

***

## 3. Blueprint di Mitigazione

### A. Nginx (`nginx.conf`)
```nginx
location ~* /wp-content/upgrade/ {
    deny all;
    return 403;
}

location ~* ^/wp-content/(uploads|upgrade|languages|mu-plugins)/.*\.php$ {
    deny all;
    return 403;
}
```

### B. Apache (`.htaccess`)
```apache
<IfModule mod_authz_core.c>
    <FilesMatch "\.(php|php[0-9]|phtml|pl|py|jsp|asp|sh|cgi)$">
        Require all denied
    </FilesMatch>
</IfModule>
Options -Indexes
```

### C. WordPress (`wp-config.php`)
```php
define('WP_TEMP_DIR', dirname(__DIR__) . '/tmp/');
define('DISALLOW_FILE_EDIT', true);
define('DISALLOW_FILE_MODS', true);
```

### D. Cloudflare WAF Rule
```cloudflare
(http.request.uri.path contains "/wp-content/upgrade/") or
(http.request.uri.path contains "/wp-content/uploads/" and http.request.uri.path contains ".php")
```

***

## 4. Consultazione Online

Consulta la guida interattiva in produzione:  
[https://tavardt-italia.github.io/wordpress-upgrade-race-checker-it/](https://tavardt-italia.github.io/wordpress-upgrade-race-checker-it/)

***

## Link Utili

* **Portale Aziendale:** https://ag.tavardt.com/it/
* **Suite di Diagnostica:** https://tools.tavardt.com/it/
* **Contatto Tecnico:** https://ag.tavardt.com/it/contatto/

***

© 2026 TAVARDT. Tutti i diritti riservati.
