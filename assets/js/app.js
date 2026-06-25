/* app.js — WireGuard ⇄ MikroTik config generator
 * Vanilla JS, no framework. Depends on: wireguard.js, iputils.js, i18n.js,
 * vendor/qrcode-generator.js, vendor/jszip.min.js
 */
(function () {
  "use strict";

  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var t = function (k) { return window.I18N.t(k); };

  // ---------- state ----------
  var state = {
    server: { priv: "", pub: "" },
    clients: [] // { name, ip, priv, pub, psk }
  };

  // ---------- helpers ----------
  function val(id) { return $("#" + id).value.trim(); }
  function intVal(id) { return parseInt($("#" + id).value, 10); }

  function sanitizeFilename(s) {
    return String(s).replace(/[^a-zA-Z0-9._-]+/g, "_").replace(/^_+|_+$/g, "") || "config";
  }
  function sanitizeComment(s) { return String(s).replace(/["\r\n]/g, "").trim(); }
  function sanitizeJsonStr(s) { return String(s).replace(/['"\r\n]/g, "").trim(); }

  function readSettings() {
    return {
      endpointHost: val("endpointHost"),
      listenPort: val("listenPort"),
      ifaceName: val("ifaceName") || "wg0",
      wgCidr: val("wgCidr"),
      serverIp: val("serverIp"),
      firstClientIp: val("firstClientIp"),
      clientCount: Math.max(1, intVal("clientCount") || 1),
      namePrefix: val("namePrefix") || "wire",
      tunnelMode: val("tunnelMode"),
      extraAllowed: val("extraAllowed"),
      dns: val("dns"),
      mtu: val("mtu"),
      keepalive: val("keepalive"),
      usePsk: $("#usePsk").checked,
      keyMode: val("serverKeyMode")
    };
  }

  function showError(msg) {
    var el = $("#formError");
    if (!msg) { el.hidden = true; el.textContent = ""; return false; }
    el.hidden = false; el.textContent = msg; return true;
  }

  // ---------- validation ----------
  function validate(s) {
    var IP = window.IPUtils;
    if (!s.endpointHost) return t("errEndpoint");
    var port = parseInt(s.listenPort, 10);
    if (!(port >= 1 && port <= 65535)) return t("errPort");
    var net = IP.parseCidr(s.wgCidr);
    if (!net) return t("errCidr");
    if (!IP.isValidIp(s.serverIp) || !IP.ipInCidr(s.serverIp, s.wgCidr)) return t("errServerIp");
    if (!IP.isValidIp(s.firstClientIp) || !IP.ipInCidr(s.firstClientIp, s.wgCidr)) return t("errFirstIp");
    var firstInt = IP.ipToInt(s.firstClientIp);
    var lastInt = firstInt + s.clientCount - 1;
    // must stay inside subnet and below the broadcast address
    if (lastInt >= net.broadcast) return t("errCount");
    if (s.keyMode === "existing" && !val("serverPub")) return t("errServerPub");
    return null;
  }

  // ---------- key management ----------
  function ensureServerKeys(forceNew) {
    var mode = val("serverKeyMode");
    if (mode === "existing") {
      state.server.pub = val("serverPub");
      state.server.priv = ""; // not needed / not known
      return;
    }
    if (forceNew || !state.server.priv) {
      var kp = wireguard.generateKeypair();
      state.server.priv = kp.privateKey;
      state.server.pub = kp.publicKey;
      $("#serverPriv").value = kp.privateKey;
      $("#serverPub").value = kp.publicKey;
    } else {
      // honor manual edits to the private key field
      var pv = val("serverPriv");
      if (pv && pv !== state.server.priv) {
        var pub = wireguard.publicFromPrivate(pv);
        if (pub) { state.server.priv = pv; state.server.pub = pub; $("#serverPub").value = pub; }
      }
    }
  }

  function syncClients(s, forceNewAll) {
    var IP = window.IPUtils;
    var firstInt = IP.ipToInt(s.firstClientIp);
    var want = s.clientCount;

    // resize
    while (state.clients.length > want) state.clients.pop();
    while (state.clients.length < want) state.clients.push(null);

    for (var i = 0; i < want; i++) {
      var c = state.clients[i];
      if (!c || forceNewAll) {
        var kp = wireguard.generateKeypair();
        var defaultName = s.namePrefix + "-" + (i + 1);
        c = {
          name: (c && c.name) ? c.name : defaultName,
          priv: kp.privateKey,
          pub: kp.publicKey,
          psk: kp.preSharedKey
        };
        // if name was auto and prefix changed, refresh it
        state.clients[i] = c;
      }
      c.ip = IP.intToIp(firstInt + i);
    }
  }

  // ---------- config text builders ----------
  function allowedIps(s) {
    if (s.tunnelMode === "full") return "0.0.0.0/0";
    var parts = [s.wgCidr];
    if (s.extraAllowed) {
      s.extraAllowed.split(",").forEach(function (p) {
        p = p.trim();
        if (p && parts.indexOf(p) === -1) parts.push(p);
      });
    }
    return parts.join(", ");
  }

  // true when the client DNS points at the router's own tunnel IP
  function dnsViaRouter(s) {
    if (!s.dns) return false;
    return s.dns.split(",").map(function (x) { return x.trim(); }).indexOf(s.serverIp) !== -1;
  }

  function buildClientConf(c, s) {
    var L = [];
    L.push("[Interface]");
    L.push("# " + c.name);
    L.push("PrivateKey = " + c.priv);
    L.push("Address = " + c.ip + "/32");
    if (s.dns) L.push("DNS = " + s.dns);
    if (s.mtu) L.push("MTU = " + s.mtu);
    L.push("");
    L.push("[Peer]");
    L.push("PublicKey = " + state.server.pub);
    if (s.usePsk) L.push("PresharedKey = " + c.psk);
    L.push("AllowedIPs = " + allowedIps(s));
    L.push("Endpoint = " + s.endpointHost + ":" + s.listenPort);
    if (s.keepalive) L.push("PersistentKeepalive = " + s.keepalive);
    return L.join("\n");
  }

  function buildServerScript(s) {
    var IP = window.IPUtils;
    var net = IP.parseCidr(s.wgCidr);
    var L = [];
    var existing = (s.keyMode === "existing");

    L.push("# ===== WireGuard setup for MikroTik (RouterOS v7) =====");
    L.push("# Interface: " + s.ifaceName + "  |  Port: " + s.listenPort + "  |  Subnet: " + s.wgCidr);
    L.push("# Generated by the WireGuard ⇄ MikroTik generator");
    L.push("");

    if (!existing) {
      L.push("/interface wireguard");
      L.push('add name=' + s.ifaceName + ' listen-port=' + s.listenPort +
        (s.mtu ? ' mtu=' + s.mtu : '') + ' private-key="' + state.server.priv + '"');
      L.push("");
      L.push("/ip address");
      L.push('add address=' + s.serverIp + '/' + net.prefix + ' interface=' + s.ifaceName + ' comment="WireGuard"');
      L.push("");
      L.push("/ip firewall filter");
      L.push('add chain=input action=accept protocol=udp dst-port=' + s.listenPort +
        ' comment="Allow WireGuard"');
      L.push("# NOTE: if your input chain ends with a drop rule, move this accept ABOVE it.");
      if (s.tunnelMode === "full") {
        L.push("");
        L.push("/ip firewall nat");
        L.push('add chain=srcnat action=masquerade src-address=' + s.wgCidr +
          ' out-interface=ether1 comment="WireGuard NAT (change ether1 to your WAN)"');
        L.push("/ip firewall filter");
        L.push('add chain=forward action=accept src-address=' + s.wgCidr + ' comment="Allow WireGuard forward"');
      }
      if (dnsViaRouter(s)) {
        L.push("");
        L.push("# Router acts as DNS for clients (DNS = " + s.serverIp + ")");
        L.push("/ip dns");
        L.push("set allow-remote-requests=yes");
        L.push("/ip firewall filter");
        L.push('add chain=input action=accept protocol=udp dst-port=53 in-interface=' + s.ifaceName + ' comment="Allow DNS from WireGuard"');
        L.push('add chain=input action=accept protocol=tcp dst-port=53 in-interface=' + s.ifaceName + ' comment="Allow DNS from WireGuard"');
      }
      L.push("");
    } else {
      L.push("# Existing server selected — only peers are added below.");
      L.push("# (Server interface, IP address and firewall are assumed to be configured.)");
      L.push("");
    }

    L.push("/interface wireguard peers");
    state.clients.forEach(function (c) {
      L.push('add interface=' + s.ifaceName +
        ' public-key="' + c.pub + '"' +
        (s.usePsk ? ' preshared-key="' + c.psk + '"' : '') +
        ' allowed-address=' + c.ip + '/32' +
        ' comment="' + sanitizeComment(c.name) + '"');
    });
    return L.join("\n");
  }

  function getRestBase() {
    var scheme = val("routerScheme") || "https";
    var host = val("routerHost") || "192.168.88.1";
    var port = val("routerPort");
    return scheme + "://" + host + (port ? ":" + port : "");
  }

  function buildRestSteps(s) {
    var IP = window.IPUtils;
    var net = IP.parseCidr(s.wgCidr);
    var steps = [];
    var existing = (s.keyMode === "existing");

    if (!existing) {
      var ifBody = { name: s.ifaceName, "listen-port": String(s.listenPort), "private-key": state.server.priv };
      if (s.mtu) ifBody.mtu = String(s.mtu);
      steps.push({ label: "interface", path: "/rest/interface/wireguard", body: ifBody });
      steps.push({ label: "ip-address", path: "/rest/ip/address", body: { address: s.serverIp + "/" + net.prefix, interface: s.ifaceName, comment: "WireGuard" } });
      steps.push({ label: "firewall", path: "/rest/ip/firewall/filter", body: { chain: "input", action: "accept", protocol: "udp", "dst-port": String(s.listenPort), comment: "Allow WireGuard" } });
      if (s.tunnelMode === "full") {
        steps.push({ label: "nat", path: "/rest/ip/firewall/nat", body: { chain: "srcnat", action: "masquerade", "src-address": s.wgCidr, "out-interface": "ether1", comment: "WireGuard NAT" } });
      }
      if (dnsViaRouter(s)) {
        steps.push({ method: "POST", label: "dns-allow-remote", path: "/rest/ip/dns/set", body: { "allow-remote-requests": "yes" } });
        steps.push({ label: "firewall-dns-udp", path: "/rest/ip/firewall/filter", body: { chain: "input", action: "accept", protocol: "udp", "dst-port": "53", "in-interface": s.ifaceName, comment: "Allow DNS from WireGuard" } });
        steps.push({ label: "firewall-dns-tcp", path: "/rest/ip/firewall/filter", body: { chain: "input", action: "accept", protocol: "tcp", "dst-port": "53", "in-interface": s.ifaceName, comment: "Allow DNS from WireGuard" } });
      }
    }
    state.clients.forEach(function (c) {
      var body = { interface: s.ifaceName, "public-key": c.pub, "allowed-address": c.ip + "/32", comment: sanitizeJsonStr(c.name) };
      if (s.usePsk) body["preshared-key"] = c.psk;
      steps.push({ label: "peer " + c.name, path: "/rest/interface/wireguard/peers", body: body });
    });
    return steps;
  }

  function buildCurl(s) {
    var base = getRestBase();
    var user = val("routerUser") || "admin";
    var pass = val("routerPass") || "PASSWORD";
    var steps = buildRestSteps(s);
    var L = [];
    L.push("# RouterOS v7 REST API must be enabled: /ip service> enable www-ssl (https) or www (http)");
    L.push('SRV="' + base + '"');
    L.push('U="' + user + '"; P="' + pass.replace(/"/g, '') + '"');
    L.push("");
    steps.forEach(function (st) {
      L.push("# " + st.label);
      L.push("curl -k -u \"$U:$P\" -X " + (st.method || "PUT") + " \"$SRV" + st.path + "\" \\");
      L.push("  -H 'content-type: application/json' \\");
      L.push("  -d '" + JSON.stringify(st.body) + "'");
      L.push("");
    });
    return L.join("\n");
  }

  // ---------- QR ----------
  function drawQr(canvas, text) {
    var qr;
    try { qr = qrcode(0, "M"); qr.addData(text); qr.make(); }
    catch (e) { qr = qrcode(0, "L"); qr.addData(text); qr.make(); }
    var count = qr.getModuleCount();
    var cell = Math.max(3, Math.round(260 / (count + 8)));
    var margin = cell * 4;
    var dim = cell * count + margin * 2;
    canvas.width = dim; canvas.height = dim;
    var ctx = canvas.getContext("2d");
    ctx.fillStyle = "#ffffff"; ctx.fillRect(0, 0, dim, dim);
    ctx.fillStyle = "#000000";
    for (var r = 0; r < count; r++) {
      for (var col = 0; col < count; col++) {
        if (qr.isDark(r, col)) ctx.fillRect(margin + col * cell, margin + r * cell, cell, cell);
      }
    }
  }

  // ---------- download ----------
  function downloadBlob(filename, blob) {
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1500);
  }
  function downloadText(filename, text) {
    downloadBlob(filename, new Blob([text], { type: "text/plain;charset=utf-8" }));
  }

  // ---------- rendering ----------
  function renderClients(s) {
    var wrap = $("#clients");
    wrap.innerHTML = "";
    if (!state.clients.length) {
      wrap.innerHTML = '<p class="empty">' + t("emptyClients") + "</p>";
      return;
    }
    state.clients.forEach(function (c, idx) {
      var conf = buildClientConf(c, s);
      var card = document.createElement("div");
      card.className = "client";
      card.dataset.idx = idx;
      card.innerHTML =
        '<div class="client-head">' +
          '<input class="client-name" type="text" value="' + escapeAttr(c.name) + '" />' +
          '<span class="client-ip">' + c.ip + "</span>" +
        "</div>" +
        '<div class="qr-box"><canvas></canvas></div>' +
        '<pre class="client-conf"></pre>' +
        '<div class="client-actions">' +
          '<button class="btn" data-act="conf">' + t("cDownloadConf") + "</button>" +
          '<button class="btn" data-act="qr">' + t("cDownloadQr") + "</button>" +
          '<button class="btn" data-act="copy">' + t("cCopy") + "</button>" +
          '<button class="btn" data-act="regen">' + t("cRegen") + "</button>" +
        "</div>";
      wrap.appendChild(card);
      card.querySelector(".client-conf").textContent = conf;
      drawQr(card.querySelector("canvas"), conf);
    });
  }

  function escapeAttr(s) { return String(s).replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;"); }

  function renderDeploy(s) {
    $("#serverScript").textContent = buildServerScript(s);
    $("#curlScript").textContent = buildCurl(s);
  }

  // ---------- main build ----------
  function build(forceNew) {
    var s = readSettings();
    var err = validate(s);
    if (err) { showError(err); return false; }
    showError(null);

    ensureServerKeys(forceNew);
    syncClients(s, forceNew);
    renderClients(s);
    renderDeploy(s);
    $("#downloadAllBtn").disabled = false;
    persistWorking();
    return true;
  }

  // rebuild text/QR without making new keys (for live setting tweaks)
  function rebuild() {
    if (!state.clients.length) return;
    build(false);
  }

  // ---------- push (browser → router) ----------
  function logPush(msg) {
    var el = $("#pushLog");
    el.textContent += msg + "\n";
    el.scrollTop = el.scrollHeight;
  }

  async function pushToRouter() {
    var s = readSettings();
    var err = validate(s);
    if (err) { $("#pushLog").textContent = err; return; }
    if (!state.clients.length) build(false);

    var scheme = val("routerScheme") || "https";
    var base = getRestBase();

    $("#pushLog").textContent = "";
    // an HTTPS page (e.g. GitHub Pages) cannot call an HTTP router → blocked outright
    if (location.protocol === "https:" && scheme === "http") {
      logPush("✗ " + t("pushMixedContent"));
      logPush("→ " + t("pushTipCors"));
      return;
    }

    logPush(t("pushStart"));
    var user = val("routerUser") || "admin";
    var pass = val("routerPass") || "";
    var auth = "Basic " + btoa(user + ":" + pass);
    var steps = buildRestSteps(s);

    for (var i = 0; i < steps.length; i++) {
      var st = steps[i];
      logPush("→ " + st.label);
      try {
        var res = await fetch(base + st.path, {
          method: st.method || "PUT",
          headers: { "Content-Type": "application/json", "Authorization": auth },
          body: JSON.stringify(st.body)
        });
        var txt = await res.text();
        logPush(res.ok ? "  ✓ ok" : "  ✗ HTTP " + res.status + " " + txt.slice(0, 160));
      } catch (e) {
        logPush("  ✗ " + e.message + " — " + t("pushBlocked"));
        if (scheme === "https") logPush("  1) " + t("pushTipCert") + " " + base + "/rest");
        logPush("  2) " + t("pushTipCors"));
        return;
      }
    }
    logPush(t("pushDone"));
  }

  // ---------- zip ----------
  function downloadAll() {
    if (!state.clients.length) return;
    var s = readSettings();
    var zip = new JSZip();
    var folder = zip.folder("clients");
    state.clients.forEach(function (c) {
      folder.file(sanitizeFilename(c.name) + ".conf", buildClientConf(c, s));
    });
    zip.file("mikrotik-setup.rsc", buildServerScript(s));
    zip.file("auto-add-curl.sh", buildCurl(s));
    zip.generateAsync({ type: "blob" }).then(function (blob) {
      downloadBlob("wireguard-configs.zip", blob);
    });
  }

  // ---------- copy ----------
  function copyText(text, btn) {
    function done() {
      if (!btn) return;
      var old = btn.textContent;
      btn.textContent = t("copied"); btn.classList.add("copied");
      setTimeout(function () { btn.textContent = old; btn.classList.remove("copied"); }, 1200);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
    } else { fallbackCopy(text); done(); }
  }
  function fallbackCopy(text) {
    var ta = document.createElement("textarea");
    ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); } catch (e) {}
    ta.remove();
  }

  // ---------- events ----------
  function bind() {
    $("#generateBtn").addEventListener("click", function () { build(true); });
    $("#regenServerBtn").addEventListener("click", function () {
      var sel = $("#serverKeyMode");
      if (sel.value === "existing") { sel.value = "generate"; toggleKeyMode(); }
      var kp = wireguard.generateKeypair();
      state.server.priv = kp.privateKey; state.server.pub = kp.publicKey;
      $("#serverPriv").value = kp.privateKey; $("#serverPub").value = kp.publicKey;
      rebuild();
    });
    $("#downloadAllBtn").addEventListener("click", downloadAll);
    $("#pushBtn").addEventListener("click", pushToRouter);

    // tabs
    document.querySelectorAll(".tab").forEach(function (tab) {
      tab.addEventListener("click", function () {
        document.querySelectorAll(".tab").forEach(function (x) { x.classList.remove("active"); });
        tab.classList.add("active");
        var name = tab.dataset.tab;
        document.querySelectorAll(".tabpanel").forEach(function (p) {
          p.hidden = (p.dataset.panel !== name);
        });
        // router credentials are only relevant for the curl + push tabs
        $("#credsBlock").hidden = (name === "script");
      });
    });

    // copy buttons (deploy tab)
    document.querySelectorAll(".copy-btn").forEach(function (b) {
      b.addEventListener("click", function () {
        var target = $(b.dataset.copy);
        if (target) copyText(target.textContent, b);
      });
    });

    // live rebuild on settings change (keys preserved)
    var liveIds = ["endpointHost", "listenPort", "ifaceName", "wgCidr", "serverIp",
      "firstClientIp", "clientCount", "namePrefix", "tunnelMode", "extraAllowed",
      "dns", "mtu", "keepalive", "usePsk"];
    var deb;
    liveIds.forEach(function (id) {
      var el = $("#" + id);
      var ev = (el.type === "checkbox" || el.tagName === "SELECT") ? "change" : "input";
      el.addEventListener(ev, function () {
        clearTimeout(deb);
        deb = setTimeout(rebuild, 250);
      });
    });

    // creds change -> rebuild curl only (cheap) + remember (password excluded)
    ["routerScheme", "routerHost", "routerPort", "routerUser", "routerPass"].forEach(function (id) {
      var el = $("#" + id);
      var ev = (el.tagName === "SELECT") ? "change" : "input";
      el.addEventListener(ev, function () {
        if (state.clients.length) $("#curlScript").textContent = buildCurl(readSettings());
        persistWorking();
      });
    });

    // profiles
    $("#saveProfileBtn").addEventListener("click", saveProfile);
    $("#deleteProfileBtn").addEventListener("click", deleteProfile);
    $("#profileSelect").addEventListener("change", function () {
      if (this.value) loadProfileByName(this.value);
      $("#deleteProfileBtn").disabled = !this.value;
    });

    // backup / restore / reset
    $("#backupBtn").addEventListener("click", exportBackup);
    $("#restoreBtn").addEventListener("click", function () { $("#restoreFile").click(); });
    $("#restoreFile").addEventListener("change", function () {
      if (this.files && this.files[0]) importBackup(this.files[0]);
      this.value = "";
    });
    $("#resetBtn").addEventListener("click", resetAll);

    // download deploy scripts as files
    $("#downloadPs1Btn").addEventListener("click", function () {
      var s = readSettings(); if (validate(s)) return;
      downloadText("auto-add-mikrotik.ps1", buildPowerShell(s));
    });
    $("#downloadShBtn").addEventListener("click", function () {
      var s = readSettings(); if (validate(s)) return;
      downloadText("auto-add-mikrotik.sh", buildCurl(s));
    });

    // tunnel mode toggles extra-allowed visibility
    $("#tunnelMode").addEventListener("change", updateTunnelUi);

    // server key mode
    $("#serverKeyMode").addEventListener("change", toggleKeyMode);
    $("#serverPriv").addEventListener("input", function () {
      if (val("serverKeyMode") !== "generate") return;
      var pub = wireguard.publicFromPrivate(val("serverPriv"));
      if (pub) { state.server.priv = val("serverPriv"); state.server.pub = pub; $("#serverPub").value = pub; rebuild(); }
    });
    $("#serverPub").addEventListener("input", function () {
      if (val("serverKeyMode") !== "existing") return;
      state.server.pub = val("serverPub"); rebuild();
    });

    // delegated client card events
    var grid = $("#clients");
    grid.addEventListener("input", function (e) {
      if (!e.target.classList.contains("client-name")) return;
      var card = e.target.closest(".client");
      var idx = parseInt(card.dataset.idx, 10);
      state.clients[idx].name = e.target.value;
      var s = readSettings();
      card.querySelector(".client-conf").textContent = buildClientConf(state.clients[idx], s);
      drawQr(card.querySelector("canvas"), card.querySelector(".client-conf").textContent);
      renderDeploy(s); // names appear in comments / curl
    });
    grid.addEventListener("click", function (e) {
      var btn = e.target.closest("button[data-act]");
      if (!btn) return;
      var card = btn.closest(".client");
      var idx = parseInt(card.dataset.idx, 10);
      var c = state.clients[idx];
      var s = readSettings();
      var conf = buildClientConf(c, s);
      var act = btn.dataset.act;
      if (act === "conf") downloadText(sanitizeFilename(c.name) + ".conf", conf);
      else if (act === "qr") {
        card.querySelector("canvas").toBlob(function (blob) {
          downloadBlob(sanitizeFilename(c.name) + ".png", blob);
        });
      } else if (act === "copy") copyText(conf, btn);
      else if (act === "regen") {
        var kp = wireguard.generateKeypair();
        c.priv = kp.privateKey; c.pub = kp.publicKey; c.psk = kp.preSharedKey;
        var nc = buildClientConf(c, s);
        card.querySelector(".client-conf").textContent = nc;
        drawQr(card.querySelector("canvas"), nc);
        renderDeploy(s);
      }
    });

    // language toggle
    $("#langToggle").addEventListener("click", function () {
      window.I18N.apply(window.I18N.lang === "fa" ? "en" : "fa");
    });
  }

  function updateTunnelUi() {
    $("#extraAllowedField").style.display = (val("tunnelMode") === "full") ? "none" : "";
  }
  // visibility only — never touches the keys (used when loading a profile)
  function updateKeyModeUi() {
    var existing = val("serverKeyMode") === "existing";
    $("#serverPrivField").style.display = existing ? "none" : "";
    if (existing) {
      $("#serverPub").removeAttribute("readonly");
      $("#serverPub").placeholder = "paste server public key";
    } else {
      $("#serverPub").setAttribute("readonly", "readonly");
    }
  }
  function toggleKeyMode() {
    var existing = val("serverKeyMode") === "existing";
    updateKeyModeUi();
    if (existing) {
      $("#serverPub").value = ""; state.server.pub = "";
    } else {
      ensureServerKeys(false);
    }
    rebuild();
  }

  // ---------- profiles / persistence ----------
  // fields that make up a saved profile (password is intentionally NOT stored)
  var SAVE_FIELDS = ["endpointHost", "listenPort", "ifaceName", "wgCidr", "serverIp",
    "firstClientIp", "clientCount", "namePrefix", "tunnelMode", "extraAllowed",
    "dns", "mtu", "keepalive", "serverKeyMode", "serverPriv", "serverPub",
    "routerScheme", "routerHost", "routerPort", "routerUser"];
  var LS_LAST = "wg_last", LS_PROFILES = "wg_profiles", LS_ACTIVE = "wg_active";

  function collectValues() {
    var d = {};
    SAVE_FIELDS.forEach(function (id) { var el = $("#" + id); if (el) d[id] = el.value; });
    d.usePsk = $("#usePsk").checked;
    return d;
  }
  function applyValues(d) {
    if (!d) return;
    SAVE_FIELDS.forEach(function (id) {
      if (d[id] !== undefined) { var el = $("#" + id); if (el) el.value = d[id]; }
    });
    if (d.usePsk !== undefined) $("#usePsk").checked = !!d.usePsk;
    // sync server-key state from the restored inputs (no regeneration)
    state.server.priv = $("#serverPriv").value;
    state.server.pub = $("#serverPub").value;
    updateKeyModeUi();
    updateTunnelUi();
  }
  function lsGet(k, fallback) { try { return localStorage.getItem(k); } catch (e) { return fallback; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }
  function lsDel(k) { try { localStorage.removeItem(k); } catch (e) {} }

  function persistWorking() { lsSet(LS_LAST, JSON.stringify(collectValues())); }
  function restoreWorking() {
    var raw = lsGet(LS_LAST);
    if (!raw) return false;
    try { applyValues(JSON.parse(raw)); return true; } catch (e) { return false; }
  }
  function getProfiles() { try { return JSON.parse(lsGet(LS_PROFILES) || "{}"); } catch (e) { return {}; } }
  function setProfiles(obj) { lsSet(LS_PROFILES, JSON.stringify(obj)); }

  function refreshProfiles() {
    var sel = $("#profileSelect");
    var active = lsGet(LS_ACTIVE) || "";
    var names = Object.keys(getProfiles()).sort();
    sel.innerHTML = "";
    var ph = document.createElement("option");
    ph.value = ""; ph.setAttribute("data-i18n", "profileLoadPlaceholder");
    ph.textContent = t("profileLoadPlaceholder");
    sel.appendChild(ph);
    names.forEach(function (n) {
      var o = document.createElement("option");
      o.value = n; o.textContent = n;
      sel.appendChild(o);
    });
    sel.value = (active && names.indexOf(active) !== -1) ? active : "";
    $("#deleteProfileBtn").disabled = !sel.value;
  }
  function saveProfile() {
    var current = lsGet(LS_ACTIVE) || "";
    var name = window.prompt(t("profileNamePrompt"), current);
    if (name === null) return;
    name = name.trim();
    if (!name) return;
    var profiles = getProfiles();
    profiles[name] = collectValues();
    setProfiles(profiles);
    lsSet(LS_ACTIVE, name);
    refreshProfiles();
    $("#profileSelect").value = name;
    $("#deleteProfileBtn").disabled = false;
  }
  function loadProfileByName(name) {
    var profiles = getProfiles();
    if (!profiles[name]) return;
    applyValues(profiles[name]);
    lsSet(LS_ACTIVE, name);
    build(false);              // rebuild text/QR/scripts using the restored keys
  }
  function deleteProfile() {
    var sel = $("#profileSelect");
    var name = sel.value;
    if (!name) return;
    var profiles = getProfiles();
    delete profiles[name];
    setProfiles(profiles);
    if ((lsGet(LS_ACTIVE) || "") === name) lsDel(LS_ACTIVE);
    refreshProfiles();
  }

  // ---------- backup / restore / reset ----------
  function exportBackup() {
    var data = {
      app: "wireguard-mikrotik-generator", version: 1,
      exportedAt: new Date().toISOString(),
      active: lsGet(LS_ACTIVE) || "",
      profiles: getProfiles(),
      last: collectValues()
    };
    downloadText("wg-mikrotik-backup.json", JSON.stringify(data, null, 2));
  }
  function importBackup(file) {
    var reader = new FileReader();
    reader.onload = function () {
      try {
        var data = JSON.parse(reader.result);
        if (data.profiles && typeof data.profiles === "object") {
          var profs = getProfiles();
          Object.keys(data.profiles).forEach(function (k) { profs[k] = data.profiles[k]; });
          setProfiles(profs);
        }
        if (data.active) lsSet(LS_ACTIVE, data.active);
        refreshProfiles();
        if (data.last) { applyValues(data.last); persistWorking(); build(false); }
        window.alert(t("backupImported"));
      } catch (e) { window.alert(t("backupBad")); }
    };
    reader.readAsText(file);
  }
  function resetAll() {
    if (!window.confirm(t("resetConfirm"))) return;
    lsDel(LS_LAST); lsDel(LS_PROFILES); lsDel(LS_ACTIVE);
    location.reload();
  }

  // ---------- Windows PowerShell auto-add script ----------
  function buildPowerShell(s) {
    var base = getRestBase();
    var user = val("routerUser") || "admin";
    var pass = (val("routerPass") || "PASSWORD").replace(/`/g, "``").replace(/"/g, '`"');
    var steps = buildRestSteps(s);
    var L = [];
    L.push("# WireGuard -> MikroTik auto-add (RouterOS v7 REST API)");
    L.push("# 1) On the router enable REST:  /ip service set www-ssl disabled=no");
    L.push("# 2) Run this file:  powershell -ExecutionPolicy Bypass -File .\\auto-add-mikrotik.ps1");
    L.push("");
    L.push('$Router = "' + base + '"');
    L.push('$User   = "' + user + '"');
    L.push('$Pass   = "' + pass + '"   # set the router password here');
    L.push("");
    L.push("# trust the router's self-signed certificate (Windows PowerShell 5.1)");
    L.push("if ($PSVersionTable.PSVersion.Major -lt 6) {");
    L.push("  add-type @\"");
    L.push("using System.Net; using System.Security.Cryptography.X509Certificates;");
    L.push("public class TrustAllCerts : ICertificatePolicy {");
    L.push("  public bool CheckValidationResult(ServicePoint sp, X509Certificate c, WebRequest r, int p) { return true; } }");
    L.push("\"@");
    L.push("  [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCerts");
    L.push("  [System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'");
    L.push("}");
    L.push("$extra = @{}; if ($PSVersionTable.PSVersion.Major -ge 6) { $extra['SkipCertificateCheck'] = $true }");
    L.push("");
    L.push('$auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$User`:$Pass"))');
    L.push('$headers = @{ Authorization = "Basic $auth" }');
    L.push("");
    L.push("function Send($method, $path, $json) {");
    L.push("  try {");
    L.push("    Invoke-RestMethod -Method $method -Uri \"$Router$path\" -Headers $headers -ContentType 'application/json' -Body $json @extra | Out-Null");
    L.push("    Write-Host \"  OK  $path\" -ForegroundColor Green");
    L.push("  } catch { Write-Host \"  ERR $path  ->  $($_.Exception.Message)\" -ForegroundColor Red }");
    L.push("}");
    L.push("");
    L.push('Write-Host "Adding WireGuard config to $Router ..." -ForegroundColor Cyan');
    steps.forEach(function (st) {
      L.push("Send '" + (st.method || "PUT") + "' '" + st.path + "' '" + JSON.stringify(st.body) + "'");
    });
    L.push('Write-Host "Done." -ForegroundColor Cyan');
    return L.join("\r\n");
  }

  // re-render labels when language flips (cards/deploy use translated strings)
  function refreshPushPlaceholder() {
    var log = $("#pushLog");
    if (log) log.setAttribute("data-ph", t("pushPlaceholder"));
  }

  window.App = {
    onLangChange: function () {
      refreshPushPlaceholder();
      if (state.clients.length) {
        var s = readSettings();
        renderClients(s);
        renderDeploy(s);
      }
    }
  };

  // ---------- init ----------
  document.addEventListener("DOMContentLoaded", function () {
    window.I18N.init();
    refreshPushPlaceholder();
    $("#serverPub").setAttribute("readonly", "readonly");
    bind();
    refreshProfiles();

    if (restoreWorking()) {
      // returning visitor — keep their last values + server keys
      build(false);
    } else {
      // first visit — sensible defaults + a fresh server keypair
      ensureServerKeys(true);
      updateTunnelUi();
      build(true);
    }
  });
})();
