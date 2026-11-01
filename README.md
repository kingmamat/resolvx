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
| 5 | **Full audit** | Semua di atas + scan security: port sensitif kebuka, path bocor, header keamanan kurang, cookie gak aman, CORS salah konfigurasi, PII di WHOIS, SSL lemah, AXFR kebocoran |

## Install

```bash
pip install rich httpx dnspython
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
 0  Keluar
```

Pilih angka → masukin domain/IP → hasil muncul → pencet Enter → balik ke menu.
Pilih `0` buat keluar.

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
utils/
  display.py          render rich: logo, tabel, status indicator
```

## Catatan

- **WHOIS `.id` / `.co.id`** — otomat routing ke `whois.pandi.id`. Di beberapa jaringan port 43 PANDI blocked, jadi timeout — gak crash, error ditampilin aja.
- **Propagasi DNS** — normalnya A record sama di semua resolver. Kalau beda, kemungkinan TTL masih panjang atau konfigurasi NS bermasalah.
- **Backend detection** — cara kerjanya heuristik: kalau A record masuk range IP anycast Cloudflare (`104.16.`, `172.67.`, `188.114.`, `190.93.`, `131.0.72.`) atau NS-nya `ns.cloudflare.com` → kemungkinan besar dibalikin Cloudflare. Ini bukan pengganti cek langsung di dashboard Cloudflare.
