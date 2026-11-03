# 🛡️ LogHunter

> **Educational project · مشروع تعليمي** — built to practice threat-detection logic and MITRE ATT&CK mapping. Tested on synthetic logs; not a production tool.

أداة بايثون خفيفة (بدون مكتبات خارجية) تفحص سجلات **SSH** و**خوادم الويب** و**أحداث Windows**، وتكتشف التهديدات المشتبه فيها، وتربطها بتقنيات **MITRE ATT&CK**، وتطلع تقريراً HTML.

A lightweight, dependency-free Python tool that detects suspicious activity in SSH, web server, and Windows Event logs, maps findings to MITRE ATT&CK, and generates an HTML report.

## ما الذي تكتشفه؟ / What it detects

| المصدر / Source | الاكتشاف / Detection | MITRE |
|---|---|---|
| SSH / Windows | تخمين كلمات المرور / Brute force | T1110 |
| SSH / Windows | دخول ناجح بعد تخمين / Successful login after brute force | T1078 |
| SSH | استطلاع الحسابات / Account discovery | T1087 |
| Web | حقن SQL / XSS / اجتياز المسارات — SQLi / XSS / path traversal | T1190 |
| Web | مسح واستطلاع وأدوات فحص آلية — scanning and automated scanner tools | T1595 |
| Windows | إنشاء حساب، إضافة لمجموعة المدراء — account creation, added to Administrators | T1136.001, T1098 |
| Windows | مهمة مجدولة، مسح سجل الأمان — scheduled task, security log cleared | T1053.005, T1070.001 |

كل اكتشاف يُصنَّف بدرجة خطورة (High / Medium / Low) ويُعرض مع الدليل من السجل.

## المتطلبات / Requirements

- Python 3.8+
- لا توجد مكتبات خارجية / No external dependencies

## التشغيل / Usage

```bash
python make_samples.py          # يولّد سجلات تجريبية فيها هجمات مصطنعة
python loghunter.py --ssh samples/auth.log \
                    --web samples/access.log \
                    --win samples/windows_events.csv \
                    --out report.html --json findings.json
```

افتحي `report.html` في المتصفح. يمكن تشغيل مصدر واحد فقط، مثلاً `--ssh` وحده.

مثال جاهز للمخرجات: [`sample_report.html`](sample_report.html) (15 اكتشافاً على السجلات التجريبية).

## صيغ الملفات / Input formats

- **SSH:** `auth.log` القياسي
- **Web:** Apache/Nginx بصيغة combined
- **Windows:** CSV بالأعمدة `TimeCreated,EventID,Account,SourceIP,Details` (مصدّر من Event Viewer أو PowerShell)

## الحدود المعروفة / Known limitations

- الكشف قائم على قواعد (regex وعتبات) وليس تعلّماً آلياً، فيمكن أن يعطي **false positives** ويمكن التحايل عليه.
- العتبات (thresholds) ثابتة في أعلى `loghunter.py` وتُعدَّل حسب البيئة.
- لا توجد **نافذة زمنية**: التخمين يُحسب بإجمالي المحاولات لكل IP في الملف كله، وليس خلال فترة محددة.
- فحص الويب يقتصر على الـURL و`User-Agent`، ولا يفحص محتوى طلبات POST.
- تحليل SSH يدعم عناوين IPv4 فقط.
- مُجرَّب على سجلات تجريبية مصطنعة ولم يُقيَّم على بيانات حقيقية.

## تطويرات مستقبلية / Future work

- نافذة زمنية للتخمين (مثل N محاولات خلال دقيقة).
- اختبارات آلية (unit tests) وتجربة على سجلات حقيقية وقياس false positives.
- دعم IPv6 وصيغ سجلات إضافية (JSON، Syslog).
- قواعد بصيغة Sigma وتكامل مع SIEM.

> عناوين IP في السجلات التجريبية من نطاقات التوثيق (RFC 5737) وليست حقيقية.
