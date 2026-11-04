# KMC RESOLVX

Tool buat cek kesehatan website/domain — DNS, port, WHOIS, SSL, sampai security scan.
Semua jalan paralel, ringan, tanpa dependensi aneh-aneh.

## Bisa ngapain aja?

| # | Aksi | Isi |
|---|---|---|
| 1 | **Cek DNS** | Semua record (A, AAAA, CNAME, MX, NS, TXT) dari resolver Cloudflare |
| 2 | **Cek propagasi DNS** | A record dicek di 3 resolver sekaligus (Cloudflare, Google, Quad9) — lihat konsistensi + latency masing-masing |
| 3 | **Cek server hidup gak** | Port 80/443 kebuka gak, berapa ms latency-nya, HTTP status apa, server siapa (Cloudflare, Vercel, dll) |
| 4 | **WHOIS + SSL** | Siapa yang daftarin domain, kapan kadaluarsa, nameserver apa; juga cek sertifikat SSL — issuer siapa, sisa berapa hari |
| 5 | **Full audit** | Semua di atas + scan security: port sensitif kebuka, path bocor, header keamanan kurang, cookie gak aman, CORS salah konfigurasi, PII di WHOIS, SSL lemah, AXFR kebocoran; + email auth (SPF/DKIM/DMARC); + tech fingerprint (CMS/WAF) |
| 6 | **Email auth** | Cek SPF / DKIM / DMARC — ada gak record-nya, isinya apa, score 0–3, warning (policy none, multiple SPF, gak ada report address, dsb.) |
| 7 | **Tech fingerprint** | Deteksi WAF/CDN (Cloudflare, Sucuri, Akamai, Vercel, Fastly, dll.), CMS (WordPress, Laravel, Next.js, React, dsb.), web server (nginx, Apache, IIS, dsb.) |
| 8 | **AI slop detector** | Scrape teks artikel utama dari URL, deteksi indikasi konten AI via hybrid statistik (perplexity & burstiness) + kamus kata kunci slop (EN + ID) — skor 0–100% + confidence level + pola slop terdeteksi |

## Install

```bash
pip install rich httpx dnspython requests beautifulsoup4
```

Pake Python 3.10 ke atas.

## Cara pake

```bash
python main.py
```

Nanti muncul menu, tinggal pilih nomornya:

```
 1  Cek DNS
 2  Cek propagasi DNS
 3  Cek server hidup gak
 4  WHOIS + SSL
 5  Full audit
 6  Email auth (SPF/DKIM/DMARC)
 7  Tech fingerprint (CMS/WAF)
 8  AI slop detector
 0  Keluar
```

Pilih angka → masukin domain/IP → hasil muncul → pencet Enter → balik ke menu.
Pilih `0` buat keluar.

Untuk menu 8 (AI slop), target boleh berupa **URL penuh** (mis. `https://example.com/blog/post`) — karena deteksinya ambil konten artikel, bukan domain. URL tanpa skema otomatis di-prefix `https://`.

Kalau masukin URL kayak `https://example.com`, otomatis di-strip jadi `example.com`.
Ketik non-angka atau kosongin target → dikasih tau, balik ke menu lagi.

## Struktur file

```
main.py               entry point + menu
core/
  dns_resolver.py     DNS: record lookup, propagasi, deteksi backend
  host_ping.py        TCP port probe + HTTP header check
  domain_whois.py     WHOIS (routing TLD-aware) + cek sertifikat SSL
  security_check.py   9 check security (port, path, header, TLS, WHOIS, AXFR)
  email_auth.py       SPF / DKIM / DMARC lookup + analisis
  tech_detect.py      CMS / WAF / web server fingerprinting
  ai_slop_detect.py   deteksi AI slop: scrape teks + analisis statistik/kamus
utils/
  display.py          render rich: logo, tabel, status indicator
```

## Catatan

- **WHOIS `.id` / `.co.id`** — otomat routing ke `whois.pandi.id`. Di beberapa jaringan port 43 PANDI blocked, jadi timeout — gak crash, error ditampilin aja.
- **Propagasi DNS** — normalnya A record sama di semua resolver. Kalau beda, kemungkinan TTL masih panjang atau konfigurasi NS bermasalah.
- **Backend detection** — cara kerjanya heuristik: kalau A record masuk range IP anycast Cloudflare (`104.16.`, `172.67.`, `188.114.`, `190.93.`, `131.0.72.`) atau NS-nya `ns.cloudflare.com` → kemungkinan besar dibalikin Cloudflare. Ini bukan pengganti cek langsung di dashboard Cloudflare.
- **DKIM detection** — coba 8 selector umum (default, google, mail, k1–s3, dsb.). Kalau domain pake selector custom, gak ketemu — normal, bukan bug.
- **Tech fingerprint** — HTTP fetch sekali (follow redirect), inspeksi headers + body 8KB pertama. CMS framework yang render client-side (React SPA tanpa marker server-side) mungkin gak terdeteksi.
- **AI slop detector** — fetch HTML (via requests + BeautifulSoup), buang nav/header/footer/script/style, lalu analisis: (1) variasi panjang kalimat & TTR (burstiness/perplexity proxy), (2) perulangan kalimat, (3) kemunculan kamus frasa LLM-preferred EN & ID. Skor final adalah weighted sum (40% keyword, 25% burstiness, 15% uniformitas, 20% repetisi), bukan klaim absolut — gunakan sebagai indikasi. Teks di bawah 100 kata dianggap tidak cukup data dan dilaporkan `failed`. Untuk integrasi web (Flask/FastAPI), panggil `core.ai_slop_detect.check_ai_slop(url)` — mengembalikan dict siap `json.dumps`.
