<div align="center">

# 🕯️ CheraghTunnel

**سامانه مدیریت تونل معکوس با عملکرد بالا — نوشته‌شده با Rust**

[![GitHub Release](https://img.shields.io/github/v/release/iambaradaran/cheraghtunnel?style=for-the-badge&logo=github&color=f59e0b)](https://github.com/iambaradaran/cheraghtunnel/releases/latest)
[![Build Status](https://img.shields.io/github/actions/workflow/status/iambaradaran/cheraghtunnel/release.yml?style=for-the-badge&logo=github-actions&label=CI)](https://github.com/iambaradaran/cheraghtunnel/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75+-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![Lines of Code](https://img.shields.io/badge/LOC-3.5K-green?style=for-the-badge)]()

<br/>

**چراغ‌تونل** یک سامانه یکپارچه و متن‌باز برای مدیریت تونل معکوس سرور به سرور است که شامل هسته کلاینت، سرور و پنل مدیریت تحت وب می‌شود. کل پروژه به زبان **Rust** نوشته شده و به صورت یک **باینری استاتیک واحد** (Single Static Binary) کامپایل می‌شود.

تمام رابط کاربری گلس‌مورفیک (Glassmorphism)، دیتابیس بومی SQLite و ۱۱ پروتکل انتقال درون باینری نهایی جاسازی شده‌اند.

<br/>

**`< 15 MB RAM`** &nbsp;•&nbsp; **`< 7 MB Binary`** &nbsp;•&nbsp; **`Zero Dependencies`** &nbsp;•&nbsp; **`Single Binary`**

</div>

---

## 📑 فهرست مطالب

- [معماری](#-معماری)
- [ویژگی‌های کلیدی](#-ویژگیهای-کلیدی)
- [پروفایل‌های انتقال](#-پروفایلهای-انتقال-transports)
- [نصب سریع](#-نصب-سریع)
- [استفاده](#-استفاده)
- [امنیت](#-امنیت)
- [توسعه](#-توسعه)
- [مشارکت](#-مشارکت)
- [لایسنس](#-لایسنس)

---

## 🏗 معماری

<div align="center">

```
                         ┌─────────────────────────────────────────┐
                         │           سرور ایران (Iran)              │
                         │                                         │
  ┌──────────┐           │  ┌────────────┐      ┌──────────────┐   │           ┌──────────────┐
  │  کاربر   │──:443────▶│  │ Public Port │─────▶│ Control Port │───│──────────▶│  سرور خارج   │
  │  (User)  │           │  │  Listener  │      │   Channel    │   │           │  (Kharej)    │
  └──────────┘           │  └────────────┘      └──────────────┘   │           │              │
                         │         │                    │          │           │  ┌────────┐  │
                         │         ▼                    ▼          │           │  │ :443   │  │
                         │  ┌─────────────────────────────────┐    │           │  │ Xray/  │  │
                         │  │   Relay Engine (tokio::select)  │    │           │  │ WG/..  │  │
                         │  │   + Traffic Monitor (Atomic)    │    │           │  └────────┘  │
                         │  └─────────────────────────────────┘    │           └──────────────┘
                         │                                         │
                         │  ┌─────────────────────────────────┐    │
                         │  │   Web Panel (:8000)              │    │
                         │  │   • Glassmorphic UI              │    │
                         │  │   • SQLite (embedded)            │    │
                         │  │   • SSH Auto-Deployer            │    │
                         │  │   • Live Bandwidth Meter         │    │
                         │  └─────────────────────────────────┘    │
                         └─────────────────────────────────────────┘
```

</div>

**جریان داده:**

1. **کاربر** به پورت عمومی سرور ایران (مثلاً `:443`) متصل می‌شود
2. **موتور ریلی** اتصال را از طریق کانال کنترل احراز‌هویت‌شده به سرور خارج هدایت می‌کند
3. **سرور خارج** ترافیک را به سرویس محلی (Xray, WireGuard, ...) تحویل می‌دهد
4. تمامی بایت‌ها به صورت **اتمیک** شمارش شده و به صورت **لحظه‌ای** در پنل نمایش داده می‌شوند

---

## ✨ ویژگی‌های کلیدی

| ویژگی | توضیحات |
|:---:|:---|
| 🚀 **۱۱ پروتکل انتقال** | از TCP ساده تا WebRTC و Reality TLS — انتخاب بهینه بر اساس شرایط شبکه |
| 🛡️ **پدافند غیرعامل** | وب‌سرور فریبنده (Decoy) در برابر اسکن ربات‌ها — ارسال صفحه ساختگی یا ریدایرکت |
| 🔗 **Multi-Path Failover** | سوئیچ خودکار بین چندین IP/دامنه ایران در کسری از ثانیه |
| ⚙️ **SSH Auto-Deploy** | نصب خودکار کلاینت روی سرور خارج فقط با وارد کردن مشخصات SSH |
| 📈 **مانیتور زنده** | نمایش لحظه‌ای سرعت DL/UL و مصرف CPU/RAM بدون اورهد |
| 🎨 **پنل Glassmorphic** | رابط کاربری مدرن و واکنش‌گرا با دیاگرام توپولوژی شبکه |
| 🔒 **امنیت لایه‌ای** | هش SHA-256، مقایسه زمان‌ثابت، Rate Limiting، توکن نشست تصادفی |
| 📦 **باینری واحد** | بدون وابستگی خارجی — فقط یک فایل اجرایی |
| 🪶 **فوق‌العاده سبک** | مصرف کمتر از ۱۵ مگابایت رم در زمان اجرا |

---

## 🔌 پروفایل‌های انتقال (Transports)

<table>
<tr>
<th>پروفایل</th>
<th>شناسه فنی</th>
<th>لایه</th>
<th>توضیحات</th>
<th>بهترین کاربرد</th>
</tr>
<tr><td>🔵 <b>Beam</b></td><td><code>tcpmux</code></td><td>TCP</td><td>ارتباط ساده و پرسرعت TCP موازی</td><td>عمومی</td></tr>
<tr><td>🟢 <b>Aura</b></td><td><code>httpmux</code></td><td>HTTP</td><td>شبیه‌سازی ترافیک معمولی وب HTTP/1.1</td><td>شبکه‌های محدود</td></tr>
<tr><td>🟡 <b>Nova</b></td><td><code>httpsmux</code></td><td>HTTPS</td><td>انتقال رمزنگاری‌شده با TLS کامل</td><td>امنیت بالا</td></tr>
<tr><td>🟣 <b>Glimmer</b></td><td><code>wsmux</code></td><td>WebSocket</td><td>بستر انتقال وب‌سوکت ساده</td><td>CDN / پروکسی</td></tr>
<tr><td>🔴 <b>Beacon</b></td><td><code>wssmux</code></td><td>WSS</td><td>وب‌سوکت امن با TLS — سازگار با Cloudflare</td><td>CDN + امنیت</td></tr>
<tr><td>⚡ <b>Flash</b></td><td><code>kcpmux</code></td><td>KCP/UDP</td><td>پروتکل سرعت بالا مبتنی بر UDP</td><td>گیمینگ</td></tr>
<tr><td>🌊 <b>Ray</b></td><td><code>rawmux</code></td><td>Raw UDP</td><td>ارتباط مستقیم KCP با کمترین اورهد</td><td>کمترین تأخیر</td></tr>
<tr><td>⚛️ <b>Photon</b></td><td><code>quantummux</code></td><td>TCP+FEC</td><td>ترکیب TCP و KCP با تصحیح خطا — بدون نیاز به UDP</td><td>گیمینگ بدون UDP</td></tr>
<tr><td>🏮 <b>Lantern</b></td><td><code>tunmux</code></td><td>TUN L2/L3</td><td>تونل سطح شبکه با اینترفیس مجازی TUN</td><td>تونل کامل شبکه</td></tr>
<tr><td>🌫️ <b>Mirage</b></td><td><code>realitymux</code></td><td>Reality TLS</td><td>جعل گواهینامه TLS سایت‌های معتبر (مثل مایکروسافت)</td><td>ضد تشخیص</td></tr>
<tr><td>👼 <b>Halo</b></td><td><code>webrtcmux</code></td><td>WebRTC</td><td>شبیه‌سازی ترافیک تماس تصویری (DataChannel)</td><td>ضد DPI</td></tr>
</table>

---

## 🚀 نصب سریع

### نصب خودکار (توصیه‌شده)

روی سرور ایران به عنوان `root` اجرا کنید:

```bash
curl -sSf https://raw.githubusercontent.com/iambaradaran/cheraghtunnel/main/install.sh | bash
```

اسکریپت نصب به صورت تعاملی موارد زیر را از شما می‌پرسد:

| پارامتر | توضیحات | پیش‌فرض |
|:---:|:---|:---:|
| پورت پنل | پورت دسترسی به پنل وب | `8000` |
| نام کاربری | نام کاربری ادمین | `admin` |
| کلمه عبور | رمز ورود (Enter = تصادفی) | تولید خودکار |

### دانلود باینری آماده

```bash
# Linux (amd64)
curl -sSfL -o /usr/local/bin/cheraghtunnel \
  https://github.com/iambaradaran/cheraghtunnel/releases/latest/download/cheraghtunnel-linux-amd64
chmod +x /usr/local/bin/cheraghtunnel

# macOS (Apple Silicon)
curl -sSfL -o /usr/local/bin/cheraghtunnel \
  https://github.com/iambaradaran/cheraghtunnel/releases/latest/download/cheraghtunnel-macos-arm64
chmod +x /usr/local/bin/cheraghtunnel
```

---

## 💻 استفاده

### ۱. اجرای پنل مدیریتی وب

```bash
cheraghtunnel panel --port 8000 --db-path cheraghtunnel.db
```

سپس از مرورگر به آدرس `http://YOUR_IP:8000` مراجعه کنید.

### ۲. اجرای سرور (ایران) به صورت CLI

```bash
cheraghtunnel server \
  --control-port 8090 \
  --public-port 443 \
  --token YOUR_SECRET_TOKEN \
  --protocol beam \
  --decoy https://www.microsoft.com
```

### ۳. اجرای کلاینت (خارج) به صورت CLI

```bash
cheraghtunnel client \
  --server-ip 1.1.1.1,2.2.2.2 \
  --control-port 8090 \
  --public-port 443 \
  --local-service 127.0.0.1:443 \
  --token YOUR_SECRET_TOKEN \
  --protocol beam \
  --tunnel-id 1
```

> 💡 **نکته:** با استفاده از پنل وب، می‌توانید تمام مراحل بالا را بدون خط فرمان و فقط از طریق رابط گرافیکی انجام دهید — شامل نصب خودکار کلاینت روی سرور خارج با SSH.

---

## 🔒 امنیت

چراغ‌تونل با رویکرد **دفاع در عمق** (Defense in Depth) طراحی شده است:

| لایه | مکانیزم | توضیحات |
|:---:|:---|:---|
| **احراز هویت** | توکن PSK + هدر سفارشی | هندشیک رمزنگاری‌شده بین کلاینت و سرور |
| **هش رمز عبور** | SHA-256 | رمزهای ادمین هش‌شده در دیتابیس ذخیره می‌شوند |
| **ضد حمله زمانی** | مقایسه زمان‌ثابت (Constant-Time) | تمام مقایسه‌های رمز، توکن و نام کاربری با XOR |
| **Rate Limiting** | ۵ تلاش / ۶۰ ثانیه | محافظت از پنل ورود در برابر حملات Brute-Force |
| **توکن نشست** | ۱۲۸ بیت تصادفی رمزنگاری | تولید با `rand::random` در هر ورود موفق |
| **ضد اسکن (Decoy)** | HTTP 302 / صفحه ساختگی | پاسخ فریبنده به ربات‌های Active Probing |
| **ضد Underflow** | `saturating_sub` | محافظت از Rate Limiter در برابر انحراف ساعت |
| **ضد نشت اتصال** | Explicit `shutdown()` | بستن صریح هر دو طرف ریلی هنگام قطع یک سمت |

---

## 🛠 توسعه

### پیش‌نیازها

- [Rust](https://rustup.rs/) نسخه 1.75 یا بالاتر
- SQLite (به صورت `bundled` در Cargo کامپایل می‌شود)

### کامپایل از سورس

```bash
# کلون پروژه
git clone https://github.com/iambaradaran/cheraghtunnel.git
cd cheraghtunnel

# کامپایل نسخه ریلیز
cargo build --release

# اجرا
./target/release/cheraghtunnel panel --port 8000
```

### بررسی کیفیت کد

```bash
# بررسی lint ها
cargo clippy

# اجرای تست‌ها
cargo test

# بررسی فرمت کد
cargo fmt --check
```

### ساختار پروژه

```
cheraghtunnel/
├── src/
│   ├── main.rs              # نقطه ورود CLI (clap)
│   ├── db.rs                # لایه دیتابیس SQLite
│   ├── api/
│   │   └── mod.rs           # پنل وب Axum + API ها
│   ├── tunnel/
│   │   ├── mod.rs           # موتور سرور و کلاینت تونل
│   │   ├── multiplex.rs     # ریلی دوطرفه + مانیتور ترافیک
│   │   └── transport/
│   │       └── mod.rs       # هندشیک پروتکل‌های انتقال
│   └── common/
│       ├── crypto.rs        # توابع رمزنگاری
│       ├── network.rs       # بهینه‌سازی سوکت + BBR
│       └── obfuscate.rs     # پدینگ و جیتر تصادفی
├── static/                  # فایل‌های UI (جاسازی‌شده در باینری)
│   ├── index.html
│   ├── style.css
│   └── app.js
├── .github/workflows/
│   └── release.yml          # CI/CD خودکار بیلد و ریلیز
├── install.sh               # اسکریپت نصب خودکار
└── Cargo.toml
```

---

## 🤝 مشارکت

از مشارکت شما استقبال می‌کنیم! حوزه‌های مورد نیاز:

- 🔬 **الگوریتم‌های شبیه‌سازی ترافیک** — بهبود پروفایل‌های انتقال موجود
- 🧪 **تست‌نویسی** — افزودن تست‌های واحد و یکپارچگی
- 📖 **مستندسازی** — بهبود راهنماها و مثال‌ها
- 🌐 **ترجمه** — پشتیبانی چندزبانه رابط کاربری

```bash
# فورک کنید، تغییرات را اعمال کنید و PR بزنید
git checkout -b feature/my-feature
git commit -m "feat: add my feature"
git push origin feature/my-feature
```

---

## 📜 لایسنس

این پروژه تحت لایسنس **[MIT](LICENSE)** منتشر شده است.

استفاده، تغییر و توزیع آزاد و رایگان است.

---

<div align="center">

**ساخته‌شده با ❤️ و Rust**

[🐛 گزارش باگ](https://github.com/iambaradaran/cheraghtunnel/issues) &nbsp;•&nbsp; [💡 پیشنهاد ویژگی](https://github.com/iambaradaran/cheraghtunnel/issues) &nbsp;•&nbsp; [📦 آخرین نسخه](https://github.com/iambaradaran/cheraghtunnel/releases/latest)

</div>
