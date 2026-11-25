# Centro di Hardening e Audit WordPress Upgrade Race Condition

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-italia.github.io/wordpress-upgrade-race-checker-it/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Vulnerability](https://img.shields.io/badge/Vulnerability-Race%20Condition-red.svg)](https://tavardt-italia.github.io/wordpress-upgrade-race-checker-it/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Specifica tecnica di ingegneria difensiva, modelli di configurazione per ambienti di produzione e utility deterministica di audit CLI per la neutralizzazione delle condizioni di concorrenza e dell'Esecuzione di Codice da Remoto (RCE) durante gli aggiornamenti di WordPress.

***

## Sintesi Tecnica: La Condizione di Concorrenza nell'Aggiornamento di WordPress

WordPress alimenta oltre il 40 per cento dei siti web globali. Durante le procedure di aggiornamento del core, dei temi o dei plugin, la piattaforma decomprime archivi ZIP all'interno di una cartella temporanea prima di trasferire i file nelle loro destinazioni definitive.

Per impostazione predefinita, questa estrazione avviene nella cartella `wp-content/upgrade/`, collocata direttamente all'interno della radice accessibile via web (DocumentRoot).

Quando la configurazione del server web consente l'esecuzione di script PHP nelle sottocartelle di contenuto, un utente malintenzionato può invocare i file appena decompressi durante la finestra temporale dell'operazione:
* L'attaccante monitora o stimola una procedura di aggiornamento sul sito target.
* I file PHP provvisori risultano eseguibili prima dell'applicazione finale dei permessi restrittivi.
* Chiamate HTTP dirette verso tali file innescano l'Esecuzione di Codice da Remoto (RCE) con i privilegi dell'utente del server web (`www-data` o `nginx`).

Questo repository mette a disposizione configurazioni collaudate per ambienti di produzione, schemi di isolamento perimetrale e una utility deterministica in Python (`audit_wp_race.py`) per verificare la sicurezza dell'infrastruttura.

***

## Superfici Critiche di Rischio nelle Directory WordPress

### 1. L'Esposizione Pubblica della Directory `wp-content/upgrade/`
La criticità deriva dalla presenza di una cartella temporanea di decompressione all'interno dell'albero servito via HTTP:
* **Finestra Temporale di Rischio:** Su server condivisi o con carichi elevati, l'estrazione di archivi voluminosi può richiedere diversi secondi.
* **Vettore di Attacco:** L'avversario invia raffiche simultanee di richieste HTTP verso i file in fase di scompattamento prima della loro rimozione.
* **Direttiva Difensiva:** Bloccare qualsiasi accesso HTTP diretto alla cartella `wp-content/upgrade/` e ricollocare la memoria temporanea fuori dalla DocumentRoot.

### 2. Esecuzione Non Vincolata di Script PHP nelle Cartelle di Contenuto
Le configurazioni comuni inoltrano qualsiasi richiesta con estensione `.php` al gestore FastCGI senza verificare la cartella di provenienza:
* **Finestra Temporale di Rischio:** Le cartelle di caricamento richiedono permessi di scrittura per gestire file multimediali e aggiornamenti.
* **Vettore di Attacco:** La disponibilità di permessi di scrittura unita all'autorizzazione di eseguire script genera un rischio immediato di esecuzione arbitraria.
* **Direttiva Difensiva:** Negare formalmente l'esecuzione di file PHP all'interno delle cartelle `uploads`, `upgrade`, `languages` e `mu-plugins` a livello di web server.

### 3. Elencazione Automatica delle Cartelle Attiva (Directory Listing)
I server web con opzioni standard che non inibiscono l'elencazione dei file mostrano la struttura delle cartelle:
* **Finestra Temporale di Rischio:** Consente a soggetti terzi di osservare in tempo reale i nomi dei file temporanei estratti durante l'aggiornamento.
* **Direttiva Difensiva:** Disabilitare l'indicizzazione automatica dei file in modo globale su tutti i virtual host.

***

## Modelli di Hardening per Ambienti di Produzione

Si consiglia di applicare queste configurazioni verificate per proteggere i server web di produzione:

### 1. Configurazione per Nginx (`nginx.conf`)
Interdice l'accesso diretto alla cartella temporanea e disabilita l'esecuzione di script PHP nelle directory di contenuto:

```nginx
# 1. Bloccare l accesso diretto alla cartella temporanea di upgrade
location ~* /wp-content/upgrade/ {
    deny all;
    return 403;
}

# 2. Impedire l esecuzione di PHP nelle cartelle di contenuto statico
location ~* ^/wp-content/(uploads|upgrade|languages|mu-plugins)/.*\.php$ {
    deny all;
    return 403;
}
```

### 2. Configurazione per Apache (`.htaccess`)
Inserire questa direttiva nei file `.htaccess` posizionati in `/wp-content/upgrade/` e `/wp-content/uploads/`:

```apache
# Negare l esecuzione di qualsiasi script eseguibile
<IfModule mod_authz_core.c>
    <FilesMatch "\.(php|php[0-9]|phtml|pl|py|jsp|asp|sh|cgi)$">
        Require all denied
    </FilesMatch>
</IfModule>

# Disabilitare l elencazione delle cartelle
Options -Indexes
```

### 3. Configurazione in WordPress (`wp-config.php`)
Sposta i file provvisori fuori dalla radice DocumentRoot e disabilita la modifica dei file:

```php
/* Spostare la cartella temporanea fuori dalla radice web pubblica */
define('WP_TEMP_DIR', dirname(__DIR__) . '/tmp/');

/* Disabilitare la modifica e l installazione di file dal pannello */
define('DISALLOW_FILE_EDIT', true);
define('DISALLOW_FILE_MODS', true);
```

### 4. Regola Perimetrale su Cloudflare WAF
Regola di protezione perimetrale per il blocco istantaneo delle richieste non autorizzate:

```text
(http.request.uri.path contains "/wp-content/upgrade/") or
(http.request.uri.path contains "/wp-content/uploads/" and http.request.uri.path contains ".php")
Azione: Block (Interruzione immediata della connessione)
```

***

## Utility Deterministica di Audit CLI

I browser web impongono limitazioni di sandbox e regole CORS che impediscono verifiche dirette a livello di socket e l'esame completo delle risposte HTTP. Per offrire diagnosi tecniche riproducibili e prive di telemetria, TAVARDT ha sviluppato una utility in Python concepita per i terminali dei tecnici e le pipeline di validazione continua.

### Fasi della Diagnosi Deterministica

L'utility (`audit_wp_race.py`) segue un percorso di analisi metodico:
* **Validazione URL & Raggiungibilità:** Verifica la corretta formulazione della richiesta, normalizza i protocolli e controlla la raggiungibilità dell'host.
* **Riconoscimento WordPress:** Accerta la presenza della piattaforma tramite le rotte REST API, gli asset canonici e i moduli di accesso.
* **Rilevamento Router SPA:** Distingue i reali codici 403/404 da instradamenti generici tipici delle Single Page Applications.
* **Sondaggio Percorsi Riservati:** Interroga `/wp-content/upgrade/` e file PHP di test per verificare il blocco da parte del server.
* **Punteggio Automatizzato:** Assegna una valutazione tecnica che varia da 100 (Protetto) a 25 (Vulnerabile).

### Istruzioni per l'Uso

Scaricare ed eseguire l'utility direttamente contro il dominio WordPress di destinazione:

```bash
# 1. Scaricare lo script ufficiale dal repository
curl -sO https://raw.githubusercontent.com/TAVARDT-Italia/wordpress-upgrade-race-checker-it/main/audit_wp_race.py

# 2. Eseguire l audit diretto sul dominio
python audit_wp_race.py https://vostro-dominio.com

# 3. Restituire l output in formato JSON
python audit_wp_race.py https://vostro-dominio.com -j
```

***

## Domande Frequenti di Architettura (FAQ Tecnico)

### 1. Che cosa determina la vulnerabilità di condizione di concorrenza nell'aggiornamento di WordPress?
Durante le operazioni di aggiornamento del core, dei temi o dei plugin, WordPress decomprime gli archivi ZIP nella cartella provvisoria `wp-content/upgrade/` prima di trasferire i file definitivi. Se la configurazione del web server consente l'esecuzione di script nelle cartelle di contenuto, un soggetto ostile può richiedere l'esecuzione di file PHP durante tale finestra temporale, ottenendo l'Esecuzione di Codice da Remoto con i privilegi del server web.

### 2. Per quale motivo è fondamentale impedire l'accesso HTTP alla cartella wp-content/upgrade?
La cartella `wp-content/upgrade/` è stata ideata unicamente per i processi locali del server PHP. Gli utenti esterni connessi a internet non hanno alcuna motivazione operativa per accedere a tale percorso, e consentire richieste pubbliche espone file provvisori a tentativi di sfruttamento automatizzati.

### 3. In che modo la ricollocazione della costante WP_TEMP_DIR annulla il rischio?
Impostare `WP_TEMP_DIR` all'esterno della DocumentRoot (ad esempio in `/var/www/tmp/` anziché in `/wp-content/upgrade/`) fa sì che i file decompressi risultino fisicamente irraggiungibili mediante richieste web. Anche qualora un attaccante individui il nome dei file temporanei, il server web non potrà erogarli né eseguirli poiché situati fuori dalla radice pubblica.

### 4. In che modo Nginx e Apache impediscono l'esecuzione di script nelle cartelle di contenuto?
Nginx adotta regole di posizione basate su espressioni regolari che restituiscono l'errore HTTP 403 per qualsiasi chiamata a file `.php` in tali cartelle. In Apache si impiegano file `.htaccess` con direttive `<FilesMatch>` associate a `Options -Indexes` per vietare sia l'esecuzione degli script sia la visualizzazione dell'elenco dei file.

### 5. L'utility di audit in Python produce carichi anomali sul sito esaminato?
No. L'utility opera come uno strumento diagnostico passivo che invia ordinarie richieste HTTP GET e HEAD per valutare i codici di risposta. Verifica se i percorsi restituiscono HTTP 403 o 404 anziché uno stato HTTP 200 aperto, valutando la robustezza perimetrale senza apportare alcuna modifica a file o database.

***

## Normative di Riferimento e Standard di Sicurezza

Architettura di sicurezza conforme al Regolamento Generale sulla Protezione dei Dati (GDPR, Regolamento UE 2016/679), alle prescrizioni del Garante per la Protezione dei Dati Personali e alle linee guida dell'Agenzia per la Cybersicurezza Nazionale (ACN).

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
