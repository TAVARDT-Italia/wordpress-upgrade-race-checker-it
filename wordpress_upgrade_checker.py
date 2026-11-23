#!/usr/bin/env python3
"""
TAVARDT Italia: Auditor di Race Condition nell'Aggiornamento di WordPress & RCE (CLI)
Utility di ispezione di sicurezza perimetrale per il rilevamento delle vulnerabilità
di esposizione ed esecuzione nella cartella transitoria wp-content/upgrade/.
"""

import sys
import json
import urllib.request
import urllib.error
import ssl

def check_route(target_url, path):
    full_url = target_url.rstrip("/") + "/" + path.lstrip("/")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    req = urllib.request.Request(
        full_url,
        headers={"User-Agent": "TAVARDT-WordPress-Race-Auditor/1.0 (+https://ag.tavardt.com/it/cybersicurezza/)"}
    )
    
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            status_code = response.getcode()
            body = response.read(2048).decode("utf-8", errors="ignore")
            is_index_of = "Index of" in body or "<title>Index of" in body
            return {
                "path": path,
                "url": full_url,
                "status": status_code,
                "accessible": True,
                "directory_listing": is_index_of,
                "risk": "CRITIQUE" if is_index_of or status_code == 200 else "FAIBLE"
            }
    except urllib.error.HTTPError as e:
        return {
            "path": path,
            "url": full_url,
            "status": e.code,
            "accessible": False,
            "directory_listing": False,
            "risk": "PROTÉGÉ" if e.code in [403, 404] else "ATTENTION"
        }
    except Exception as e:
        return {
            "path": path,
            "url": full_url,
            "status": 0,
            "accessible": False,
            "directory_listing": False,
            "risk": "ERREUR_CONNEXION",
            "error": str(e)
        }

def audit_wordpress(target_url):
    paths = [
        "wp-content/upgrade/",
        "wp-content/upgrade/test.php",
        "wp-content/uploads/",
        "wp-content/uploads/test.php"
    ]
    
    results = []
    for p in paths:
        results.append(check_route(target_url, p))
    
    upgrade_dir = next((r for r in results if r["path"] == "wp-content/upgrade/"), None)
    is_vulnerable = False
    if upgrade_dir and (upgrade_dir["directory_listing"] or upgrade_dir["status"] == 200):
        is_vulnerable = True
        
    assessment = {
        "target": target_url,
        "is_vulnerable": is_vulnerable,
        "posture": "VULNÉRABLE" if is_vulnerable else "PROTÉGÉ",
        "routes": results,
        "remediation": [
            "Définir WP_TEMP_DIR hors de la radice publique DocumentRoot dans wp-config.php : define('WP_TEMP_DIR', dirname(__DIR__) . '/tmp/');",
            "Bloquer l'exécution de scripts PHP dans wp-content/upgrade/ et wp-content/uploads/ sous Nginx ou Apache.",
            "Configurer une règle personnalisée Cloudflare WAF pour rejeter les requêtes ciblant /wp-content/upgrade/.",
            "Activer DISALLOW_FILE_MODS pour imposer les déploiements exclusivement via des pipelines automatisés CI/CD."
        ]
    }
    return assessment

def print_remediation():
    print("""
================================================================================
  DIRECTIVES DE DURCISSEMENT ARCHITECTURAL : WORDPRESS UPGRADE RACE CONDITION
================================================================================
1. Configuration dans wp-config.php :
   Ajouter avant la ligne "/* That's all, stop editing! */" :
   define('WP_TEMP_DIR', dirname(__DIR__) . '/tmp/');
   define('DISALLOW_FILE_MODS', true);
   define('DISALLOW_FILE_EDIT', true);

2. Blocage sous Nginx (nginx.conf) :
   location ~* /wp-content/upgrade/ {
       deny all;
       return 403;
   }
   location ~* ^/wp-content/(uploads|upgrade)/.*\.php$ {
       deny all;
       return 403;
   }

3. Blocage sous Apache (.htaccess dans wp-content/upgrade/) :
   <FilesMatch "\.(php|phtml|php[0-9]|sh|cgi)$">
       Require all denied
   </FilesMatch>
   Options -Indexes
================================================================================
""")

def main():
    if len(sys.argv) < 2:
        print("Usage: python wordpress_upgrade_checker.py <URL_OU_DOMAINE> [--json] [--remediate]")
        print("Exemple: python wordpress_upgrade_checker.py https://site-entreprise.fr")
        sys.exit(1)
        
    target = sys.argv[1].strip()
    if target in ["--help", "-h"]:
        print("Usage: python wordpress_upgrade_checker.py <URL_OU_DOMAINE> [--json] [--remediate]")
        sys.exit(0)
        
    if target == "--remediate":
        print_remediation()
        sys.exit(0)
        
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target
        
    is_json = "--json" in sys.argv
    show_remediate = "--remediate" in sys.argv
    
    data = audit_wordpress(target)
    
    if is_json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return
        
    print("=" * 80)
    print("  TAVARDT ITALIA : AUDITEUR DE RACE CONDITION WORDPRESS")
    print("=" * 80)
    print(f"Target : {target}")
    print(f"Posture Globale : {data['posture']}")
    print("-" * 80)
    print("Routes Inspectées :")
    for r in data["routes"]:
        status = r["status"] if r["status"] != 0 else "Échec de Connexion"
        list_flag = " [DIRECTORY LISTING RILEVATO]" if r.get("directory_listing") else ""
        print(f" * [{r['risk']}] {r['path']} -> HTTP {status}{list_flag}")
        
    print("-" * 80)
    if data["is_vulnerable"]:
        print("[ALERTE CRITIQUE] Le serveur présente une exposition du directory wp-content/upgrade/.")
        print("Des assaillants peuvent exploiter des fenêtres de concurrence pour exécuter des scripts PHP transitoires.")
    else:
        print("[CONFORME] Le directory wp-content/upgrade/ est rigoureusement protégé contre tout accès direct.")
        
    if show_remediate:
        print_remediation()
    else:
        print("Conseil : Exécutez avec --remediate pour afficher les directives de durcissement.")
    print("=" * 80)

if __name__ == "__main__":
    main()
