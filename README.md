# IRON

**IRON** یک تانل Reverse TCP امن برای وصل کردن سرویس‌های یک سرور پشت مسیر محدود/فیلتر به یک سرور عمومی است.

سناریوی معمول:

```text
User/Client  --->  IR/Public Server = Hub  <=== TLS/HMAC tunnel ===  EU/Service Server = Agent  --->  127.0.0.1:443
```

یعنی کاربر به پورت بازشده روی سرور ایران وصل می‌شود، ولی سرویس واقعی روی سرور خارج/Agent اجرا می‌شود.

> این پروژه VPN نیست. یک Reverse TCP Tunnel/Port Forwarder امن‌تر است.

---

## تفاوت با تونل‌های ساده‌تر

IRON نسبت به relay خام TCP این قابلیت‌ها را دارد:

- ارتباط Hub و Agent با **TLS**
- احراز هویت با **HMAC-SHA256 challenge/response**
- پشتیبانی از چند پورت با یک اتصال مرکزی از Agent به Hub
- Multiplexing چند connection روی یک control connection
- Heartbeat با `PING/PONG`
- Reconnect خودکار Agent
- نصب ساده با Bash
- سرویس systemd آماده
- hardening اولیه systemd
- TCP tuning/BBR روی Hub
- بدون dependency خارجی؛ فقط Python 3 و ابزارهای پایه لینوکس

---

## ساختار پروژه

```text
IRON/
├── iron.py                  # هسته تانل
├── install.sh               # نصب‌کننده Bash
├── config/
│   ├── hub.example.json
│   └── agent.example.json
├── systemd/
│   ├── iron-hub.service
│   └── iron-agent.service
├── scripts/
│   └── quick-test.sh
├── README.md
├── LICENSE
└── .gitignore
```

---

## نصب سریع

روی سرور ایران/سرور عمومی یا همان **Hub**:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Unknown-sir/IRON/main/install.sh)" hub
```

روی سرور خارج/سروری که سرویس اصلی روی آن اجراست یا همان **Agent**:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Unknown-sir/IRON/main/install.sh)" agent
```

اگر خواستی منوی نصبی باز شود:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Unknown-sir/IRON/main/install.sh)"
```

---

## نصب دستی از فایل‌های ریپو

```bash
git clone https://github.com/Unknown-sir/IRON.git
cd IRON
sudo bash install.sh
```

یا مستقیم:

```bash
sudo bash install.sh hub
sudo bash install.sh agent
```

---

## راه‌اندازی پیشنهادی

### 1) روی Hub / سرور ایران

```bash
sudo bash install.sh hub
```

نصب‌کننده این موارد را می‌پرسد:

- پورت کنترل TLS، پیش‌فرض `9443`
- پورت عمومی که کاربران به آن وصل می‌شوند، مثلاً `443`
- مقصد روی Agent، معمولاً `127.0.0.1:443`
- Agent ID، پیش‌فرض `default`

بعد از نصب، یک token بهت نشان می‌دهد. همان token را برای نصب Agent لازم داری.

فایل تنظیمات Hub:

```bash
sudo nano /etc/iron/hub.json
```

نمونه mapping چند پورت:

```json
"ports": [
  {
    "listen_host": "0.0.0.0",
    "listen_port": 443,
    "target_host": "127.0.0.1",
    "target_port": 443
  },
  {
    "listen_host": "0.0.0.0",
    "listen_port": 8443,
    "target_host": "127.0.0.1",
    "target_port": 8443
  }
]
```

بعد از تغییر config:

```bash
sudo systemctl restart iron-hub
```

---

### 2) روی Agent / سرور خارج

```bash
sudo bash install.sh agent
```

نصب‌کننده این موارد را می‌پرسد:

- IP یا دامنه Hub
- پورت کنترل Hub، مثلاً `9443`
- Agent ID
- token ساخته‌شده روی Hub
- حالت TLS strict یا insecure

برای امنیت بهتر، فایل certificate ساخته‌شده روی Hub را به Agent منتقل کن:

روی Hub:

```bash
sudo cat /etc/iron/hub.crt
```

محتوا را روی Agent داخل این فایل ذخیره کن:

```bash
sudo nano /etc/iron/hub.crt
```

بعد Agent را با TLS strict تنظیم کن یا در فایل `/etc/iron/agent.json` این بخش را داشته باش:

```json
"ca_file": "/etc/iron/hub.crt"
```

و این گزینه را حذف کن:

```json
"insecure_skip_verify": true
```

سپس:

```bash
sudo systemctl restart iron-agent
```

---

## دستورات مدیریت

وضعیت سرویس‌ها:

```bash
sudo systemctl status iron-hub
sudo systemctl status iron-agent
```

لاگ Hub:

```bash
sudo journalctl -u iron-hub -f
```

لاگ Agent:

```bash
sudo journalctl -u iron-agent -f
```

ری‌استارت:

```bash
sudo systemctl restart iron-hub
sudo systemctl restart iron-agent
```

حذف کامل:

```bash
sudo bash install.sh uninstall
```

---

## Firewall

روی Hub باید این پورت‌ها باز باشند:

- پورت control، پیش‌فرض `9443`
- پورت‌هایی که برای کاربران listen می‌کنی، مثلاً `443` یا `8443`

نمونه با UFW:

```bash
sudo ufw allow 9443/tcp
sudo ufw allow 443/tcp
sudo ufw reload
```

روی Agent معمولاً لازم نیست پورت tunnel را باز کنی، چون Agent خودش اتصال خروجی به Hub می‌زند.

---

## تست ساده

روی Agent یک سرویس تستی اجرا کن:

```bash
python3 -m http.server 8080 --bind 127.0.0.1
```

روی Hub در `/etc/iron/hub.json` mapping را مثلاً اینطوری کن:

```json
"ports": [
  {
    "listen_host": "0.0.0.0",
    "listen_port": 8080,
    "target_host": "127.0.0.1",
    "target_port": 8080
  }
]
```

بعد:

```bash
sudo systemctl restart iron-hub
sudo systemctl restart iron-agent
```

از سیستم خودت تست کن:

```bash
curl http://HUB_IP:8080/
```

---


- IRON فعلاً TCP را tunnel می‌کند، نه UDP.
- این نسخه برای port forwarding امن ساخته شده، نه برای ناشناس‌سازی یا VPN کامل.
- اگر سرویس مقصد خودش TLS ندارد، داده‌ها بین User و Hub خام است؛ البته مسیر Hub تا Agent داخل TLS است.

---

