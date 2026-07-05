<div align="center">

# 🕯️ CheraghTunnel (چراغ‌تونل)

**سامانه جامع مدیریت و استقرار تونل معکوس پیشرفته با کارایی فوق‌العاده بالا — نوشته‌شده با Rust**

[![GitHub Release](https://img.shields.io/github/v/release/iam4lucard/cheraghtunnel?style=for-the-badge&logo=github&color=f59e0b)](https://github.com/iam4lucard/cheraghtunnel/releases/latest)
[![Build Status](https://img.shields.io/github/actions/workflow/status/iam4lucard/cheraghtunnel/release.yml?style=for-the-badge&logo=github-actions&label=CI)](https://github.com/iam4lucard/cheraghtunnel/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75+-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)

<br/>

**چراغ‌تونل** یک پروژه امنیتی، یکپارچه و متن‌باز برای دور زدن محدودیت‌های شدید اینترنت و برقراری ارتباط سرور به سرور (معکوس) است. این سامانه شامل هسته قدرتمند کلاینت/سرور، موتور پروکسی چندپروتکله و پنل وب مدرن با رابط کاربری گلس‌مورفیک (Glassmorphism) است که همگی در قالب **یک باینری واحد استاتیک** بدون هیچ‌گونه وابستگی خارجی کامپایل شده‌اند.

<br/>

**`< 15 MB RAM`** &nbsp;•&nbsp; **`< 7 MB Binary`** &nbsp;•&nbsp; **`Zero Dependencies`** &nbsp;•&nbsp; **`Single Binary`**

</div>

---

## 📑 فهرست مطالب

- [ویژگی‌های کلیدی](#-ویژگی‌های-کلیدی)
- [پروتکل‌های انتقال (Transports)](#-پروتکل‌های-انتقال-transports)
- [پنل مدیریت تحت وب](#-پنل-مدیریت-تحت-وب)
- [نصب سریع](#-نصب-سریع)
- [راهنمای استفاده CLI](#-راهنمای-استفاده-cli)
- [مکانیسم امنیتی و استتار](#-مکانیسم-امنیتی-و-استتار)
- [توسعه و کامپایل از سورس](#-توسعه-و-کامپایل-از-سورس)
- [لایسنس](#-لایسنس)

---

## ✨ ویژگی‌های کلیدی

* 🚀 **۱۲ پروتکل انتقال متنوع:** از TCP ساده تا لایه‌های WebRTC ،Reality و Hysteria جهت عبور از دیوارهای آتش مختلف بر اساس شرایط شبکه.
* 🔄 **پرش پورت پویا (Dynamic Port Hopping):** تغییر زمان‌بندی‌شده و رمزنگاری‌شده‌ی پورت کنترلر (هر ۵ دقیقه) روی سرور ایران جهت خنثی‌سازی فیلترینگ فعال بر اساس پورت و رفتارسنجی شبکه.
* ⚙️ **استقرار خودکار تک‌کلیکی (SSH Auto-Deploy):** پیکربندی و اجرای خودکار کلاینت روی سرور خارج به کمک اتصال SSH (پشتیبانی از نام‌کاربری/کلمه عبور و کلیدهای خصوصی SSH).
* 💾 **پشتیبان‌گیری و بازیابی یکپارچه:** دانلود آسان کل تنظیمات، نودها و تانل‌ها در قالب یک فایل پشتیبان SQLite و امکان بازیابی آنی آن از طریق پنل بدون نیاز به ری‌استارت سرور.
* 📉 **Telemetry و پایش زنده کیفیت:** رسم نمودارهای گرافیکی لحظه‌ای از میزان پینگ (RTT) و پکت‌لاست (Packet Loss) بین سرور ایران و خارج به همراه مانیتور سخت‌افزاری زنده (CPU/RAM).
* 🛡️ **وب‌سرور فریبنده (Decoy Defense):** پاسخ‌دهی هوشمند به اسکن‌های فعال (Active Probing) فیلترینگ با شبیه‌سازی وب‌سایت‌های معتبر یا ریدایرکت خودکار ترافیک غیرمجاز.
* 📦 **سبک و بدون وابستگی:** کل سرور پنل وب، کلاینت، موتور رله و پایگاه‌داده‌ی بومی SQLite در یک فایل باینری با مصرف رم ناچیز قرار دارند.

---

## 🔌 پروتکل‌های انتقال (Transports)

| پروفایل | شناسه فنی | لایه انتقال | توضیحات | بهترین کاربرد |
|:---:|:---:|:---:|:---|:---|
| 🔵 **Beam** | `tcpmux` | TCP | ارتباط ساده و بسیار سریع TCP موازی با مالتی‌پلکسینگ | عمومی و پرسرعت |
| 🟢 **Aura** | `httpmux` | HTTP | شبیه‌سازی ترافیک و هدرهای معمولی وب HTTP/1.1 | شبکه‌های بسیار محدود |
| 🟡 **Nova** | `httpsmux` | HTTPS | انتقال تماماً رمزنگاری‌شده با TLS معتبر و کامل | امنیت حداکثری |
| 🟣 **Glimmer** | `wsmux` | WebSocket | وب‌سوکت ساده جهت عبور از شبکه‌های توزیع محتوا | عبور از CDN |
| 🔴 **Beacon** | `wssmux` | WSS | وب‌سوکت امن با لایه TLS — سازگار با کلودفلر | CDN با امنیت بالا |
| ⚡ **Flash** | `kcpmux` | KCP/UDP | پروتکل سرعت بالای گیمینگ مبتنی بر UDP | بازی‌های آنلاین و پینگ پایین |
| 🌊 **Ray** | `rawmux` | Raw UDP | ارتباط مستقیم KCP با کمترین اورهد در سطح سوکت | ارتباطات بلادرنگ |
| ⚛️ **Photon** | `quantummux` | TCP+FEC | ترکیب نوآورانه‌ی TCP و KCP با تصحیح خطا بدون استفاده از UDP | دور زدن فیلترینگ UDP |
| 🏮 **Lantern** | `tunmux` | TUN L2/L3 | تونل سطح شبکه با ساخت اینترفیس مجازی سیستم‌عامل | انتقال کل ترافیک سیستم |
| 🌫️ **Mirage** | `realitymux` | Reality TLS | جعل گواهینامه TLS سایت‌های معتبر خارجی (مانند مایکروسافت) | عبور از دیوار آتش هوشمند |
| 👼 **Halo** | `webrtcmux` | WebRTC | شبیه‌سازی پکت‌ها مشابه تماس‌های صوتی/تصویری اینترنتی | دور زدن DPI سخت‌گیرانه |
| 🌶️ **Hysteria** | `hysteriamux` | QUIC/UDP | پروتکل بر پایه QUIC با قابلیت تنظیم پهنای باند و سرعت | شبکه‌های پر‌نویز و نوسان‌دار |

---

## 🎨 پنل مدیریت تحت وب

پنل وب چراغ‌تونل امکان مدیریت بدون نیاز به خط فرمان را با امکانات زیر فراهم می‌سازد:
* **داشبورد مانیتورینگ:** نمایش درصد مصرف منابع سرور (سی‌پی‌یو و رم) به همراه وضعیت اتصالات فعال به صورت پویا.
* **مدیریت نودها (Iran/Kharej):** تعریف سرورها با نقش‌های مختلف و ثبت اطلاعات SSH جهت استقرار خودکار کلاینت‌ها.
* **ایجاد و ویرایش تانل:** امکان تغییر لحظه‌ای پروتکل، پورت‌ها، استتار و فعال/غیرفعال‌سازی پرش پورت (Port Hopping) تنها با چند کلیک.
* **بخش پشتیبان‌گیری:** دانلود نسخه پشتیبان دیتابیس و آپلود آنی جهت بازیابی کل سیستم در سرور جدید.

---

## 🚀 نصب سریع

### روش اول: اسکریپت نصب خودکار (توصیه‌شده)

برای نصب خودکار پنل مدیریتی، دستور زیر را به عنوان کاربر `root` روی سرور ایران خود اجرا کنید:

```bash
curl -sSf https://raw.githubusercontent.com/iam4lucard/cheraghtunnel/main/install.sh | bash
```

این اسکریپت مراحل نصب را به صورت تعاملی پیش برده و موارد زیر را از شما می‌پرسد:
* **پورت پنل وب:** پورتی که پنل روی آن بالا می‌آید (پیش‌فرض: `8000`).
* **نام کاربری و رمز عبور:** مشخصات ورود ادمین برای قفل امنیتی پنل.

پس از پایان، سرویس پنل وب به صورت یک سرویس `systemd` به نام `cheraghtunnel` ثبت شده و در پس‌زمینه اجرا می‌شود.

### روش دوم: دانلود مستقیم باینری آماده

شما می‌توانید مستقیماً باینری کامپایل‌شده‌ی آخرین نسخه را برای پلتفرم خود دریافت کنید:

```bash
# نسخه‌ی لینوکس (amd64)
curl -sSfL -o /usr/local/bin/cheraghtunnel \
  https://github.com/iam4lucard/cheraghtunnel/releases/latest/download/cheraghtunnel-linux-amd64
chmod +x /usr/local/bin/cheraghtunnel

# نسخه‌ی لینوکس (arm64)
curl -sSfL -o /usr/local/bin/cheraghtunnel \
  https://github.com/iam4lucard/cheraghtunnel/releases/latest/download/cheraghtunnel-linux-arm64
chmod +x /usr/local/bin/cheraghtunnel
```

---

## 💻 راهنمای استفاده CLI

در صورتی که می‌خواهید هسته تونل را بدون پنل وب و به صورت دستی در خط فرمان اجرا کنید:

### ۱. اجرای پنل وب با خط فرمان
```bash
cheraghtunnel panel --port 8000 --db-path /var/lib/cheraghtunnel/cheraghtunnel.db
```

### ۲. اجرای سرور (ایران)
```bash
cheraghtunnel server \
  --control-port 8090 \
  --public-port 443 \
  --token SECRET_TOKEN \
  --protocol beam \
  --decoy https://www.microsoft.com \
  --port-hopping
```

### ۳. اجرای کلاینت (خارج)
```bash
cheraghtunnel client \
  --server-ip 62.60.202.4 \
  --control-port 8090 \
  --public-port 443 \
  --local-service 127.0.0.1:1080 \
  --token SECRET_TOKEN \
  --protocol beam \
  --tunnel-id 1 \
  --port-hopping
```

---

## 🔒 مکانیسم امنیتی و استتار

چراغ‌تونل امنیت لایه‌ای و حریم خصوصی را با ویژگی‌های پیشرفته تضمین می‌کند:
* **مقایسه‌های زمان‌ثابت (Constant-Time Operations):** جلوگیری از حملات کانال جانبی تحلیل زمان (Timing Attacks) در زمان احراز هویت توکن‌ها.
* **پدافند غیرعامل در برابر اسکن‌های فعال (Decoy):** در صورتی که هرگونه درخواست غیرمجاز (مانند ربات‌های شناسایی فیلترینگ) به پورت کنترلر ارسال شود، سیستم به طور خودکار پاسخ‌های فریبنده یا ریدایرکت به وب‌سایت‌های معتبر را شبیه‌سازی می‌کند.
* **Rate Limiting هوشمند:** محافظت از پنل وب در برابر حملات Brute-force با محدودسازی تعداد ورود‌های ناموفق.
* **مکانیزم پاکسازی آنی پورت‌ها:** استفاده از آپشن‌های سوکت سیستم‌عامل (`SO_REUSEADDR` و `SO_REUSEPORT`) جهت آزادسازی فوری پورت‌ها هنگام تغییر وضعیت تانل بدون اشغال شدن پورت.

---

## 🛠 توسعه و کامپایل از سورس

### پیش‌نیازها
* [Rust و Cargo](https://rustup.rs/) نسخه 1.75 یا بالاتر
* کتابخانه توسعه SQLite (`libsqlite3-dev` در توزیع‌های دبیان/اوبونتو)

### مراحل ساخت
```bash
# کلون ریپازیتوری
git clone https://github.com/iam4lucard/cheraghtunnel.git
cd cheraghtunnel

# بیلد نسخه نهایی (Release)
cargo build --release

# اجرای فایل خروجی
./target/release/cheraghtunnel panel --port 8000
```

---

## 📜 لایسنس

این پروژه تحت لایسنس **[MIT](LICENSE)** توسعه داده می‌شود و استفاده، ویرایش و توزیع آن به هر شکلی کاملاً آزاد و رایگان است.

<div align="center">

**ساخته‌شده با ❤️ و قدرت Rust**

[🐛 گزارش مشکلات](https://github.com/iam4lucard/cheraghtunnel/issues) &nbsp;•&nbsp; [💡 ثبت ایده جدید](https://github.com/iam4lucard/cheraghtunnel/issues) &nbsp;•&nbsp; [📦 نسخه‌های منتشر شده](https://github.com/iam4lucard/cheraghtunnel/releases)

</div>
