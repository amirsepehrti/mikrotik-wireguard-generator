# WireGuard ⇄ MikroTik Config Generator

A single‑page, **100% client‑side** tool that generates WireGuard **client configs**
(`.conf` + QR code) and the matching **MikroTik RouterOS v7** setup — either as a
paste‑ready script, ready‑to‑run `curl` commands, or a best‑effort direct push.

No backend, no build step. Open the HTML and it works. All key generation happens
locally in your browser — nothing is uploaded anywhere.

> Inspired by [markeclaudio/mikrotik-wireguard-config-generator](https://github.com/markeclaudio/mikrotik-wireguard-config-generator),
> rebuilt from scratch with the bugs fixed (see below).

---

## Features

- 🔑 **Curve25519 keys in the browser** (private / public / preshared) using the official WireGuard JS implementation.
- 🌐 **Proper addressing** — any IPv4 subnet/CIDR, validated; server IP, first client IP and client count all checked to fit the subnet.
- 📱 **QR code + `.conf` download** per client, plus **Download all** as a `.zip` (configs + `mikrotik-setup.rsc` + `auto-add-curl.sh`).
- 🪛 **Three ways to deploy to MikroTik:**
  1. **RouterOS script** — paste into Winbox › New Terminal (most reliable).
  2. **Auto add (`curl`)** — give it the router user/pass and run the generated REST‑API commands.
  3. **Push (advanced)** — best‑effort `fetch()` from the browser (see caveats).
- 🧠 **Existing server mode** — paste only the server public key to add peers to a router that already has WireGuard.
- 🌍 **Split / full tunnel** with automatic NAT + forward rules for full tunnel.
- 🇮🇷 / 🇬🇧 **Bilingual UI** (English / فارسی, RTL aware), dark theme, mobile friendly.
- 📦 **Offline‑friendly** — `qrcode-generator` and `JSZip` are bundled locally in `vendor/`.

---

## Run it

### Locally
Just open `index.html` in a browser — that's it. (For the clipboard API and
`fetch` push to behave best, you can also serve it:)

```bash
# any static server, e.g.
python -m http.server 8080
# then open http://localhost:8080
```

### GitHub Pages
1. Push this folder to a repo.
2. **Settings → Pages → Build and deployment → Deploy from a branch**, pick `main` / root.
3. Open `https://<user>.github.io/<repo>/`.

A `.nojekyll` file is included so all assets are served as‑is.

---

## Deploying to MikroTik

### RouterOS REST API (for the `curl` / push methods)
RouterOS v7 only. Enable the web service on the router first:

```
/ip service set www-ssl disabled=no   # https  (recommended)
# or
/ip service set www disabled=no       # http
```

### About the in‑browser "Push" tab
Calling the router directly from a web page is usually blocked by the browser:

- **Mixed content** — an `https://` page (e.g. GitHub Pages) cannot call an `http://` router.
- **CORS** — RouterOS does not send `Access-Control-Allow-Origin` headers, so the browser rejects the response.
- **Self‑signed TLS** — the router's default certificate isn't trusted.

So push is *best‑effort* and mostly useful behind a reverse proxy that adds CORS headers.
**The reliable "automatic" path is the `curl` tab** (or pasting the RouterOS script) —
you supply the credentials once and everything is created for you.

---

## What was fixed vs. the original

| Issue in the original | Fix here |
|---|---|
| `endpoint-address` set to the client's own tunnel IP on each peer (wrong for roaming clients) | Peers are added **without** `endpoint-address`/port. |
| No automatic add to the router | Generated `curl` REST commands + best‑effort browser push. |
| Everything loaded from CDNs (Vue 2 EOL, qrcode, jszip, file‑saver) — breaks offline | Vanilla JS, libraries **bundled locally**. |
| `downloadqrcodes` did string concatenation instead of addition (broken loop) | Rewritten; numeric handling throughout. |
| Hard‑coded `/24`, `.1`, single 3‑octet network, no validation | Full CIDR support with validation. |
| New server keypair on every reload; couldn't target an existing server | Persistent server keys + **existing server** mode. |
| Hard‑coded MTU / keepalive / no PSK toggle / no NAT for full tunnel | All configurable; NAT + forward auto‑added for full tunnel. |
| `<table>` layout, not responsive | Responsive dark UI, mobile friendly, EN/FA. |

---

## Project layout

```
index.html
assets/
  css/styles.css
  js/app.js          # app logic (vanilla)
  js/iputils.js      # IPv4/CIDR helpers (MIT)
  js/wireguard.js    # Curve25519 key gen (WireGuard, GPL-2.0)
  js/i18n.js         # EN/FA strings
vendor/
  qrcode-generator.js # MIT
  jszip.min.js        # MIT
```

## Licensing note
`assets/js/wireguard.js` is the official WireGuard browser key generator and is
**GPL‑2.0** (header preserved). The rest of the project is MIT. If GPL is a problem
for you, swap that one file for a permissive X25519 implementation.

## Security
- Treat generated `.conf` files and QR codes as secrets — they contain private keys.
- Prefer the preshared‑key option for post‑quantum‑ish resistance.
- The server private key only appears when you let the tool generate it; in *existing* mode it never touches the browser.
