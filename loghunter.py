#!/usr/bin/env python3
"""LogHunter - أداة فحص السجلات واكتشاف التهديدات (SSH / Web / Windows Events)

الاستخدام:
  python loghunter.py --ssh samples/auth.log --web samples/access.log \
                      --win samples/windows_events.csv --out report.html
"""
import argparse, csv, html, json, re
from collections import Counter, defaultdict
from datetime import datetime
from urllib.parse import unquote_plus

BF_THRESHOLD = 5        # محاولات فاشلة قبل اعتبارها تخمين
SCAN_404 = 15           # عدد 404 قبل اعتباره مسح
ENUM_USERS = 5          # عدد مستخدمين غير موجودين قبل اعتباره استطلاع

SEV_ORDER = {"High": 0, "Medium": 1, "Low": 2}
SEV_AR = {"High": "عالية", "Medium": "متوسطة", "Low": "منخفضة"}

IP = r"(\d{1,3}(?:\.\d{1,3}){3})"
SSH_FAIL = re.compile(r"Failed password for (?:invalid user )?(\S+) from " + IP)
SSH_OK = re.compile(r"Accepted (?:password|publickey) for (\S+) from " + IP)
SSH_INVALID = re.compile(r"Invalid user (\S+) from " + IP)
SSH_TS = re.compile(r"^(\w{3}\s+\d+\s[\d:]{8})")

WEB_LINE = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) \S+ "[^"]*" "([^"]*)"')
SQLI = re.compile(r"(union\s+select|\bor\s+1=1|'\s*or\s*'|sleep\(|information_schema|drop\s+table|;--)", re.I)
XSS = re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=)", re.I)
TRAVERSAL = re.compile(r"(\.\./|/etc/passwd|win\.ini)", re.I)
SCANNER_UA = re.compile(r"(sqlmap|nikto|nmap|masscan|gobuster|dirbuster|wpscan)", re.I)


def finding(source, ftype, sev, ip, count, tid, tname, desc, evidence=""):
    return dict(source=source, type=ftype, severity=sev, ip=ip, count=count,
                mitre=tid, mitre_name=tname, desc=desc, evidence=evidence[:160])


# ---------------------------------------------------------------- SSH
def analyze_ssh(path):
    out, fails, users, bad_users = [], Counter(), defaultdict(set), defaultdict(set)
    reported_ok, first_ts = set(), {}
    with open(path, errors="replace") as f:
        for line in f:
            ts = (SSH_TS.match(line) or [None, ""])[1]
            if m := SSH_FAIL.search(line):
                user, ip = m.groups()
                fails[ip] += 1
                users[ip].add(user)
                first_ts.setdefault(ip, ts)
            elif m := SSH_INVALID.search(line):
                bad_users[m.group(2)].add(m.group(1))
            elif m := SSH_OK.search(line):
                user, ip = m.groups()
                if fails[ip] >= BF_THRESHOLD and ip not in reported_ok:
                    reported_ok.add(ip)
                    out.append(finding(
                        "SSH", "دخول ناجح بعد تخمين", "High", ip, fails[ip],
                        "T1078", "Valid Accounts",
                        f"تسجيل دخول ناجح للحساب {user} بعد {fails[ip]} محاولة فاشلة: احتمال اختراق الحساب",
                        line.strip()))
    for ip, n in fails.items():
        if n >= BF_THRESHOLD:
            out.append(finding(
                "SSH", "تخمين كلمات المرور", "High" if n >= 20 else "Medium", ip, n,
                "T1110", "Brute Force",
                f"{n} محاولة فاشلة على {len(users[ip])} حساب مختلف، أولها عند {first_ts[ip]}"))
    for ip, us in bad_users.items():
        if len(us) >= ENUM_USERS:
            out.append(finding(
                "SSH", "استطلاع الحسابات", "Medium", ip, len(us),
                "T1087", "Account Discovery",
                f"تجربة {len(us)} اسم مستخدم غير موجود: {', '.join(sorted(us)[:5])}..."))
    return out


# ---------------------------------------------------------------- Web
def analyze_web(path):
    out, c404, hits = [], Counter(), defaultdict(list)
    with open(path, errors="replace") as f:
        for line in f:
            m = WEB_LINE.match(line)
            if not m:
                continue
            ip, ts, method, url, status, ua = m.groups()
            u = unquote_plus(url)
            if status == "404":
                c404[ip] += 1
            if SQLI.search(u):
                hits[(ip, "حقن SQL", "T1190", "Exploit Public-Facing Application", "High")].append(u)
            if XSS.search(u):
                hits[(ip, "XSS", "T1190", "Exploit Public-Facing Application", "Medium")].append(u)
            if TRAVERSAL.search(u):
                hits[(ip, "اجتياز المسارات", "T1190", "Exploit Public-Facing Application", "High")].append(u)
            if SCANNER_UA.search(ua):
                hits[(ip, "أداة فحص آلية", "T1595", "Active Scanning", "Medium")].append(ua)
    for (ip, ftype, tid, tname, sev), ev in hits.items():
        out.append(finding("Web", ftype, sev, ip, len(ev), tid, tname,
                           f"{len(ev)} طلب مطابق لنمط {ftype}", ev[0]))
    for ip, n in c404.items():
        if n >= SCAN_404:
            out.append(finding("Web", "مسح واستطلاع", "Medium", ip, n, "T1595", "Active Scanning",
                               f"{n} طلب أعطى 404: مسح عن صفحات أو ملفات مخفية"))
    return out


# ---------------------------------------------------------------- Windows
WIN_SINGLE = {
    "4720": ("إنشاء حساب جديد", "Medium", "T1136.001", "Create Account: Local Account"),
    "4732": ("إضافة مستخدم لمجموعة مدراء", "High", "T1098", "Account Manipulation"),
    "1102": ("مسح سجل الأمان", "High", "T1070.001", "Clear Windows Event Logs"),
    "4698": ("إنشاء مهمة مجدولة", "Medium", "T1053.005", "Scheduled Task"),
}


def analyze_win(path):
    """CSV بالأعمدة: TimeCreated,EventID,Account,SourceIP,Details"""
    out, fails = [], Counter()
    reported_ok = set()
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        for r in csv.DictReader(f):
            eid, ip, acc = r["EventID"].strip(), r.get("SourceIP", "").strip(), r.get("Account", "")
            if eid == "4625":
                fails[ip] += 1
            elif eid == "4624" and fails[ip] >= BF_THRESHOLD and ip not in reported_ok:
                reported_ok.add(ip)
                out.append(finding("Windows", "دخول ناجح بعد تخمين", "High", ip, fails[ip],
                                   "T1078", "Valid Accounts",
                                   f"تسجيل دخول ناجح للحساب {acc} بعد {fails[ip]} محاولة فاشلة",
                                   f"{r['TimeCreated']} EventID 4624"))
            elif eid in WIN_SINGLE:
                name, sev, tid, tname = WIN_SINGLE[eid]
                out.append(finding("Windows", name, sev, ip or "-", 1, tid, tname,
                                   f"{name}: {acc} ({r.get('Details', '')})",
                                   f"{r['TimeCreated']} EventID {eid}"))
    for ip, n in fails.items():
        if n >= BF_THRESHOLD:
            out.append(finding("Windows", "تخمين كلمات المرور", "High" if n >= 20 else "Medium",
                               ip, n, "T1110", "Brute Force", f"{n} حدث 4625 (فشل تسجيل دخول)"))
    return out


# ---------------------------------------------------------------- Report
def bars(items):
    mx = max([v for _, v in items] or [1])
    return "".join(
        f'<div class="row"><span class="lbl">{html.escape(str(k))}</span>'
        f'<div class="bar"><i style="width:{v / mx * 100:.0f}%"></i></div><b>{v}</b></div>'
        for k, v in items)


TEMPLATE = """<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LogHunter - تقرير التهديدات</title><style>
:root{--bg:#0f172a;--card:#1e293b;--tx:#e2e8f0;--mut:#94a3b8;--hi:#ef4444;--me:#f59e0b;--lo:#22c55e;--ac:#38bdf8}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font-family:Tahoma,Arial,sans-serif;padding:24px}
h1{margin:0 0 4px}.sub{color:var(--mut);margin-bottom:20px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px}
.card{background:var(--card);border-radius:12px;padding:16px}.card h3{margin:0;color:var(--mut);font-size:14px}
.card .n{font-size:32px;font-weight:bold}.hi .n{color:var(--hi)}.me .n{color:var(--me)}.lo .n{color:var(--lo)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px;margin-bottom:20px}
.row{display:flex;align-items:center;gap:8px;margin:8px 0;font-size:14px}.lbl{width:150px;direction:ltr;text-align:right}
.bar{flex:1;background:#334155;border-radius:6px;height:12px}.bar i{display:block;height:100%;background:var(--ac);border-radius:6px}
.wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;background:var(--card);border-radius:12px;font-size:14px}
th,td{padding:10px;text-align:right;border-bottom:1px solid #334155;vertical-align:top}th{color:var(--mut)}
.tag{padding:2px 10px;border-radius:99px;font-size:12px;color:#000}.High{background:var(--hi)}.Medium{background:var(--me)}.Low{background:var(--lo)}
code{direction:ltr;display:inline-block;color:var(--ac);font-size:12px;word-break:break-all}
</style></head><body>
<h1>🛡️ LogHunter - تقرير التهديدات</h1><div class="sub">%%TIME%% | المصادر: %%SOURCES%%</div>
<div class="cards"><div class="card"><h3>إجمالي الاكتشافات</h3><div class="n">%%TOTAL%%</div></div>
<div class="card hi"><h3>خطورة عالية</h3><div class="n">%%HIGH%%</div></div>
<div class="card me"><h3>خطورة متوسطة</h3><div class="n">%%MED%%</div></div>
<div class="card lo"><h3>خطورة منخفضة</h3><div class="n">%%LOW%%</div></div></div>
<div class="grid"><div class="card"><h3>التهديدات حسب النوع</h3>%%BYTYPE%%</div>
<div class="card"><h3>أكثر عناوين IP نشاطاً</h3>%%BYIP%%</div>
<div class="card"><h3>تقنيات MITRE ATT&amp;CK</h3>%%BYMITRE%%</div></div>
<div class="wrap"><table><tr><th>الخطورة</th><th>المصدر</th><th>النوع</th><th>IP</th><th>العدد</th><th>MITRE</th><th>التفاصيل</th></tr>
%%ROWS%%</table></div></body></html>"""


def build_report(findings, sources, path):
    findings.sort(key=lambda x: (SEV_ORDER[x["severity"]], -x["count"]))
    sev = Counter(x["severity"] for x in findings)
    by_type = Counter(x["type"] for x in findings).most_common(8)
    by_ip = Counter()
    for x in findings:
        if x["ip"] != "-":
            by_ip[x["ip"]] += x["count"]
    by_mitre = Counter(f'{x["mitre"]} {x["mitre_name"]}' for x in findings).most_common(8)
    rows = "".join(
        f'<tr><td><span class="tag {x["severity"]}">{SEV_AR[x["severity"]]}</span></td>'
        f'<td>{x["source"]}</td><td>{html.escape(x["type"])}</td><td><code>{html.escape(x["ip"])}</code></td>'
        f'<td>{x["count"]}</td><td><code>{x["mitre"]}</code><br><small>{x["mitre_name"]}</small></td>'
        f'<td>{html.escape(x["desc"])}'
        + (f'<br><code>{html.escape(x["evidence"])}</code>' if x["evidence"] else "") + "</td></tr>"
        for x in findings)
    page = (TEMPLATE.replace("%%TIME%%", datetime.now().strftime("%Y-%m-%d %H:%M"))
            .replace("%%SOURCES%%", "، ".join(sources) or "-")
            .replace("%%TOTAL%%", str(len(findings))).replace("%%HIGH%%", str(sev["High"]))
            .replace("%%MED%%", str(sev["Medium"])).replace("%%LOW%%", str(sev["Low"]))
            .replace("%%BYTYPE%%", bars(by_type)).replace("%%BYIP%%", bars(by_ip.most_common(8)))
            .replace("%%BYMITRE%%", bars(by_mitre)).replace("%%ROWS%%", rows))
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)


def main():
    ap = argparse.ArgumentParser(description="LogHunter: log threat detection")
    ap.add_argument("--ssh", help="مسار auth.log")
    ap.add_argument("--web", help="مسار access.log (Apache/Nginx combined)")
    ap.add_argument("--win", help="مسار CSV لأحداث Windows")
    ap.add_argument("--out", default="report.html")
    ap.add_argument("--json", help="مسار اختياري لتصدير JSON")
    a = ap.parse_args()
    if not (a.ssh or a.web or a.win):
        ap.error("حددي ملف سجلات واحد على الأقل")

    findings, sources = [], []
    for flag, fn, name in ((a.ssh, analyze_ssh, "SSH"), (a.web, analyze_web, "Web"), (a.win, analyze_win, "Windows")):
        if flag:
            findings += fn(flag)
            sources.append(name)

    build_report(findings, sources, a.out)
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(findings, f, ensure_ascii=False, indent=2)
    sev = Counter(x["severity"] for x in findings)
    print(f"[+] {len(findings)} findings  (High={sev['High']} Medium={sev['Medium']} Low={sev['Low']})")
    for x in findings[:10]:
        print(f"  [{x['severity']:<6}] {x['source']:<7} {x['mitre']:<10} {x['ip']:<16} {x['type']}")
    print(f"[+] report: {a.out}")


if __name__ == "__main__":
    main()
