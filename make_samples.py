#!/usr/bin/env python3
"""يولّد سجلات تجريبية فيها هجمات مصطنعة للعرض (عناوين IP من نطاقات التوثيق فقط)."""
import os, random
from datetime import datetime, timedelta

random.seed(7)
os.makedirs("samples", exist_ok=True)
t0 = datetime(2026, 11, 3, 1, 0, 0)
ATT, ENUM, SCAN, WEBATT = "203.0.113.45", "198.51.100.23", "198.51.100.77", "203.0.113.99"
GOOD = ["192.0.2.10", "192.0.2.11", "192.0.2.12"]

# ---------------- SSH auth.log
lines, t = [], t0
def ssh(msg):
    global t
    t += timedelta(seconds=random.randint(1, 20))
    lines.append(f"{t.strftime('%b %e %H:%M:%S')} srv01 sshd[{random.randint(1000, 9999)}]: {msg}")

for _ in range(6):
    ssh(f"Accepted publickey for rawan from {random.choice(GOOD)} port 52211 ssh2")
for u in ["admin", "root", "test", "oracle", "postgres", "ubuntu", "git", "ftp"]:
    ssh(f"Invalid user {u} from {ENUM} port 40022")
    ssh(f"Failed password for invalid user {u} from {ENUM} port 40022 ssh2")
for i in range(40):
    ssh(f"Failed password for {random.choice(['root', 'admin', 'deploy'])} from {ATT} port {40000 + i} ssh2")
ssh(f"Accepted password for deploy from {ATT} port 41000 ssh2")
for _ in range(4):
    ssh(f"Accepted publickey for rawan from {random.choice(GOOD)} port 52300 ssh2")
open("samples/auth.log", "w").write("\n".join(lines) + "\n")

# ---------------- Web access.log
lines, t = [], t0
def web(ip, url, status=200, ua="Mozilla/5.0 (Windows NT 10.0) Chrome/120.0"):
    global t
    t += timedelta(seconds=random.randint(1, 5))
    lines.append(f'{ip} - - [{t.strftime("%d/%b/%Y:%H:%M:%S +0300")}] "GET {url} HTTP/1.1" {status} 512 "-" "{ua}"')

for _ in range(40):
    web(random.choice(GOOD), random.choice(["/", "/about", "/products", "/contact"]))
for i in range(60):
    web(SCAN, f"/{random.choice(['admin', 'backup', 'wp-login', '.git', 'phpmyadmin'])}{i}.php", 404, "Nikto/2.5.0")
for p in ["/products?id=1' OR 1=1--", "/products?id=1 UNION SELECT user,pass FROM users",
          "/search?q=<script>alert(1)</script>", "/download?file=../../../../etc/passwd",
          "/products?id=1;DROP TABLE users;--"]:
    web(WEBATT, p, 500, "sqlmap/1.7")
open("samples/access.log", "w").write("\n".join(lines) + "\n")

# ---------------- Windows events (CSV)
rows, t = [], t0
def win(eid, acc, ip="", det=""):
    global t
    t += timedelta(seconds=random.randint(1, 30))
    rows.append(f"{t.strftime('%Y-%m-%d %H:%M:%S')},{eid},{acc},{ip},{det}")

for _ in range(5):
    win(4624, "rawan", random.choice(GOOD), "Logon type 2")
for _ in range(25):
    win(4625, "Administrator", ATT, "Logon type 3")
win(4624, "Administrator", ATT, "Logon type 3")
win(4720, "svc_backup2", ATT, "New local account")
win(4732, "svc_backup2", ATT, "Added to Administrators")
win(4698, "svc_backup2", ATT, "Task: UpdateCheck")
win(1102, "Administrator", ATT, "Security log cleared")
open("samples/windows_events.csv", "w").write("TimeCreated,EventID,Account,SourceIP,Details\n" + "\n".join(rows) + "\n")
print("Samples written to ./samples")
