/* i18n.js — tiny EN/FA translation layer */
(function () {
  "use strict";

  var DICT = {
    en: {
      appTitle: "WireGuard ⇄ MikroTik Generator",
      appSubtitle: "Generate client configs, QR codes and RouterOS scripts — all in your browser.",
      badgeLocal: "🔒 100% client-side",
      settingsTitle: "Settings",
      profileLoadPlaceholder: "— Load profile —",
      btnSaveProfile: "💾 Save",
      btnDeleteProfile: "🗑 Delete",
      profileNamePrompt: "Profile name:",
      fsServer: "Server / Endpoint",
      lblEndpoint: "Endpoint host (for clients)",
      phEndpoint: "vpn.example.com or 1.2.3.4",
      lblPort: "Listen port",
      lblIface: "Interface name",
      fsAddressing: "Addressing",
      lblCidr: "Tunnel subnet (CIDR)",
      lblServerIp: "Server tunnel IP",
      lblFirstIp: "First client IP",
      lblCount: "# of clients",
      lblPrefix: "Name prefix",
      fsClientOpts: "Client options",
      lblTunnel: "Routing",
      optSplit: "Split tunnel (only listed nets)",
      optFull: "Full tunnel (0.0.0.0/0)",
      lblExtra: "Extra AllowedIPs (behind router)",
      lblDns: "Client DNS",
      lblMtu: "MTU",
      lblKeepalive: "Keepalive (s)",
      lblPsk: "Use preshared key (extra security)",
      fsKeys: "Server keys",
      lblKeyMode: "Mode",
      optGenerate: "Generate new server keypair",
      optExisting: "Use existing server (paste public key)",
      lblServerPriv: "Server private key",
      lblServerPub: "Server public key",
      hintKeys: "In \"existing\" mode only the public key is needed — clients embed it. The private key never leaves the server.",
      btnGenerate: "⚡ Generate",
      btnRegenServer: "🔁 New server keys",
      btnDownloadAll: "📦 Download all (.zip)",
      btnBackup: "⬇ Backup",
      btnRestore: "⬆ Restore",
      btnReset: "♻ Reset all",
      resetConfirm: "Erase ALL saved profiles and settings and start fresh? This cannot be undone.",
      backupImported: "Backup restored.",
      backupBad: "Invalid backup file.",
      btnPs1: "⬇ Windows PowerShell (.ps1)",
      btnShFile: "⬇ bash (.sh)",
      hintPs1: "The .ps1 runs on Windows (double-click won't work — run it as shown in the file). It ignores self-signed certs and isn't affected by CORS, so it actually adds everything to the router.",
      deployTitle: "Deploy to MikroTik",
      tabScript: "RouterOS script",
      tabCurl: "Auto add (curl)",
      tabPush: "Push (advanced)",
      hintScript: "Most reliable. Paste this into the router terminal (Winbox > New Terminal, or SSH).",
      btnCopy: "Copy",
      placeholderGenerate: "Press “Generate” to build the output…",
      hintCurl: "Give the router credentials above and these commands add everything for you (RouterOS v7 REST API). Run in a bash/sh terminal that can reach the router.",
      lblScheme: "Scheme",
      lblRouterHost: "Router address",
      lblRouterPort: "Port (opt.)",
      lblRouterUser: "Username",
      lblRouterPass: "Password",
      hintPush: "Best-effort browser → router via REST API using the credentials above. Often blocked by CORS / mixed-content / self-signed certs — if it fails, use the curl tab.",
      btnPush: "🚀 Push to router",
      pushPlaceholder: "Status will appear here after you press “Push to router”.",
      clientsTitle: "Clients",
      emptyClients: "No clients yet — fill in the settings and press Generate.",
      footerNote: "All key generation happens locally in your browser. Nothing is uploaded.",
      // dynamic
      cDownloadConf: "⬇ .conf",
      cDownloadQr: "⬇ QR",
      cCopy: "Copy",
      cRegen: "🔁 keys",
      copied: "Copied!",
      pushStart: "Connecting to router…",
      pushDone: "Done. Check the router for the new interface and peers.",
      pushMixedContent: "This page is HTTPS but the router scheme is HTTP — the browser blocks that (mixed content).",
      pushBlocked: "the browser blocked the request",
      pushTipCert: "open this URL in a new tab and accept the certificate, then retry:",
      pushTipCors: "RouterOS sends no CORS headers, so the browser may still block it. The “Auto add (curl)” tab always works — copy those commands into a terminal.",
      errCidr: "Invalid tunnel subnet (CIDR).",
      errServerIp: "Server tunnel IP is invalid or not inside the subnet.",
      errFirstIp: "First client IP is invalid or not inside the subnet.",
      errCount: "Client count does not fit in the subnet.",
      errPort: "Listen port must be 1–65535.",
      errEndpoint: "Endpoint host is required.",
      errServerPub: "Existing mode: paste the server public key."
    },
    fa: {
      appTitle: "سازنده‌ی WireGuard برای میکروتیک",
      appSubtitle: "ساخت کانفیگ کلاینت، بارکد QR و اسکریپت روترOS — همه داخل مرورگر.",
      badgeLocal: "🔒 کاملاً سمت کاربر",
      settingsTitle: "تنظیمات",
      profileLoadPlaceholder: "— بارگذاری پروفایل —",
      btnSaveProfile: "💾 ذخیره",
      btnDeleteProfile: "🗑 حذف",
      profileNamePrompt: "نام پروفایل:",
      fsServer: "سرور / Endpoint",
      lblEndpoint: "آدرس سرور (برای کلاینت‌ها)",
      phEndpoint: "vpn.example.com یا 1.2.3.4",
      lblPort: "پورت گوش‌دادن",
      lblIface: "نام اینترفیس",
      fsAddressing: "آدرس‌دهی",
      lblCidr: "ساب‌نت تونل (CIDR)",
      lblServerIp: "آی‌پی تونل سرور",
      lblFirstIp: "اولین آی‌پی کلاینت",
      lblCount: "تعداد کلاینت",
      lblPrefix: "پیشوند نام",
      fsClientOpts: "تنظیمات کلاینت",
      lblTunnel: "مسیریابی",
      optSplit: "تونل تفکیکی (فقط شبکه‌های مشخص)",
      optFull: "تونل کامل (0.0.0.0/0)",
      lblExtra: "AllowedIPs اضافه (پشت روتر)",
      lblDns: "DNS کلاینت",
      lblMtu: "MTU",
      lblKeepalive: "Keepalive (ثانیه)",
      lblPsk: "استفاده از Preshared key (امنیت بیشتر)",
      fsKeys: "کلیدهای سرور",
      lblKeyMode: "حالت",
      optGenerate: "ساخت زوج‌کلید جدید سرور",
      optExisting: "سرور موجود (paste کلید عمومی)",
      lblServerPriv: "کلید خصوصی سرور",
      lblServerPub: "کلید عمومی سرور",
      hintKeys: "در حالت «موجود» فقط کلید عمومی لازم است — کلاینت‌ها آن را در خود دارند. کلید خصوصی هرگز از سرور خارج نمی‌شود.",
      btnGenerate: "⚡ ساخت",
      btnRegenServer: "🔁 کلید جدید سرور",
      btnDownloadAll: "📦 دانلود همه (.zip)",
      btnBackup: "⬇ بکاپ",
      btnRestore: "⬆ بازیابی",
      btnReset: "♻ ریست کامل",
      resetConfirm: "همه‌ی پروفایل‌ها و تنظیمات ذخیره‌شده پاک شوند و از اول شروع شود؟ این کار قابل بازگشت نیست.",
      backupImported: "بکاپ بازیابی شد.",
      backupBad: "فایل بکاپ نامعتبر است.",
      btnPs1: "⬇ پاورشل ویندوز (.ps1)",
      btnShFile: "⬇ bash (.sh)",
      hintPs1: "فایل .ps1 روی ویندوز اجرا می‌شود (دابل‌کلیک کار نمی‌کند — طبق راهنمای داخل فایل اجرا کن). گواهی self-signed را نادیده می‌گیرد و درگیر CORS نیست، پس واقعاً همه‌چیز را روی روتر اضافه می‌کند.",
      deployTitle: "نصب روی میکروتیک",
      tabScript: "اسکریپت روترOS",
      tabCurl: "افزودن خودکار (curl)",
      tabPush: "ارسال مستقیم (پیشرفته)",
      hintScript: "مطمئن‌ترین راه. این را در ترمینال روتر paste کن (Winbox › New Terminal یا SSH).",
      btnCopy: "کپی",
      placeholderGenerate: "برای ساخت خروجی، «ساخت» را بزن…",
      hintCurl: "نام‌کاربری/رمز روتر را بالا بده تا این دستورها همه‌چیز را خودکار اضافه کنند (REST API روترOS v7). در ترمینال bash/sh که به روتر دسترسی دارد اجرا کن.",
      lblScheme: "پروتکل",
      lblRouterHost: "آدرس روتر",
      lblRouterPort: "پورت (اختیاری)",
      lblRouterUser: "نام کاربری",
      lblRouterPass: "رمز عبور",
      hintPush: "تلاش مستقیم مرورگر → روتر از طریق REST API با اطلاعات ورود بالا. معمولاً به‌خاطر CORS / mixed-content / گواهی self-signed مسدود می‌شود — اگر کار نکرد از تب curl استفاده کن.",
      btnPush: "🚀 ارسال به روتر",
      pushPlaceholder: "بعد از زدن «ارسال به روتر»، وضعیت اینجا نمایش داده می‌شود.",
      clientsTitle: "کلاینت‌ها",
      emptyClients: "هنوز کلاینتی نیست — تنظیمات را پر کن و «ساخت» را بزن.",
      footerNote: "تمام ساخت کلیدها به‌صورت محلی در مرورگر انجام می‌شود. چیزی آپلود نمی‌شود.",
      cDownloadConf: "⬇ فایل .conf",
      cDownloadQr: "⬇ بارکد",
      cCopy: "کپی",
      cRegen: "🔁 کلید",
      copied: "کپی شد!",
      pushStart: "در حال اتصال به روتر…",
      pushDone: "انجام شد. اینترفیس و peerها را روی روتر بررسی کن.",
      pushMixedContent: "این صفحه HTTPS است ولی پروتکل روتر HTTP — مرورگر این را مسدود می‌کند (mixed content).",
      pushBlocked: "مرورگر درخواست را مسدود کرد",
      pushTipCert: "این آدرس را در تب جدید باز کن و گواهی را بپذیر، بعد دوباره امتحان کن:",
      pushTipCors: "روترOS هدر CORS نمی‌فرستد، پس ممکن است باز هم مرورگر مسدود کند. تب «افزودن خودکار (curl)» همیشه کار می‌کند — آن دستورها را در ترمینال اجرا کن.",
      errCidr: "ساب‌نت تونل (CIDR) نامعتبر است.",
      errServerIp: "آی‌پی تونل سرور نامعتبر است یا داخل ساب‌نت نیست.",
      errFirstIp: "اولین آی‌پی کلاینت نامعتبر است یا داخل ساب‌نت نیست.",
      errCount: "تعداد کلاینت در ساب‌نت جا نمی‌شود.",
      errPort: "پورت باید بین ۱ تا ۶۵۵۳۵ باشد.",
      errEndpoint: "آدرس سرور لازم است.",
      errServerPub: "حالت موجود: کلید عمومی سرور را paste کن."
    }
  };

  var current = "en";

  function t(key) {
    return (DICT[current] && DICT[current][key]) || (DICT.en[key]) || key;
  }

  function apply(lang) {
    current = DICT[lang] ? lang : "en";
    document.documentElement.lang = current;
    document.documentElement.dir = current === "fa" ? "rtl" : "ltr";

    document.querySelectorAll("[data-i18n]").forEach(function (el) {
      var key = el.getAttribute("data-i18n");
      var val = t(key);
      // keep inner <strong> etc. for a couple of rich strings
      if (/[<&]/.test(val)) { el.innerHTML = val; } else { el.textContent = val; }
    });
    document.querySelectorAll("[data-i18n-ph]").forEach(function (el) {
      el.setAttribute("placeholder", t(el.getAttribute("data-i18n-ph")));
    });
    var toggle = document.getElementById("langToggle");
    if (toggle) toggle.textContent = current === "fa" ? "English" : "فارسی";

    try { localStorage.setItem("wg_lang", current); } catch (e) {}
    if (window.App && window.App.onLangChange) window.App.onLangChange();
  }

  window.I18N = {
    t: t,
    apply: apply,
    get lang() { return current; },
    init: function () {
      var saved = "en";
      try { saved = localStorage.getItem("wg_lang") || "en"; } catch (e) {}
      apply(saved);
    }
  };
})();
