# CHANGELOG_FIXES.md

Memori institusional proyek ini — akar tiap bug yang sudah diperbaiki, supaya
sesi berikutnya tak mengulang kesalahan yang sama. Entri terbaru di ATAS.

Format tiap entri:
```
### Fix #N — Judul Singkat: Gejala + Akar
| | |
|---|---|
| **Tanggal** | YYYY-MM-DD |
| **File** | path + fungsi yang diubah |
| **Masalah** | gejala konkret (sertakan angka/log nyata) |
| **Akar** | penyebab sebenarnya, bukan sekadar apa yang salah |
| **Fix** | apa yang diubah dan mengapa pendekatan itu |
| **Verifikasi** | bukti nyata: test/log/repro sebelum-sesudah |
| **Pelajaran** | pola kesalahan yang perlu dihindari |
```

<!-- ENTRI BARU DI BAWAH BARIS INI -->
### Fix #6 — Tambah modul AI slop detector (menu 8)
| | |
|---|---|
| **Tanggal** | 2026-11-04 |
| **File** | `core/ai_slop_detect.py` (baru), `main.py` (opsi 8 + import + validasi input URL), `README.md` |
| **Masalah** | tidak ada bug spesifik — penambahan fitur deteksi konten AI. Sebelum integrasi, smoke test menu 8 crash `NameError: name 'name' is not defined` di `main.py:400` karena dispatch masih memanggil variabel lama `name` setelah refaktoring jadi `target`. |
| **Akar** | refactoring blok input (menambah opsi URL penuh untuk menu 8) mengganti nama variabel `name` → `target` di blok validasi, tapi baris `dispatch[choice](name)` tak ikut diubah. |
| **Fix** | ganti `dispatch[choice](name)` jadi `dispatch[choice](target)` di `main.py:400`. Detektor inti: `check_ai_slop(url)` fetch HTML via `requests` (UA browser), extract teks utama via `BeautifulSoup` (buang nav/header/footer/script/style), lalu hybrid score: 40% rasio kamus slop EN+ID, 25% burstiness (CV panjang kalimat), 15% uniformitas TTR, 20% repetisi kalimat. Teks < 100 kata → `failed`. |
| **Verifikasi** | `test_ai_slop_offline.py` 5 test lulus: (1) ekstraksi membuang noise, (2) kamus EN hits≥3 & ID hits≥2 & word boundary benar, (3) skor sintetik AI=53/54 vs human=0 & slang ID=9 (kontras tajam), (4) URL tak ada → `failed: ConnectionError`, (5) port tak buka → `failed: ConnectTimeout` dalam 15.0 detik (timeout efektif). Menu smoke test `printf "8\nhttps://blog.google\n\n0\n"` → skor 0%, 763 kata, sukses tanpa crash. |
| **Pelajaran** | setelah refactor nama variabel di blok besar (mis. per-cabangan input), grep semua referensinya di scope bawah — tidak cukup compile-check karena `name` adalah nama lokal yang sah di fungsi lain, Python tidak error saat compile, hanya runtime. Selalu jalankan smoke test penuh, bukan hanya `py_compile`. |
### Fix #5 — Tambah modul email_auth (SPF/DKIM/DMARC) + tech_detect (CMS/WAF)
| | |
|---|---|
| **Tanggal** | 2026-11-02 |
| **File** | `core/email_auth.py` (baru), `core/tech_detect.py` (baru), `main.py` (opsi 6 & 7), `utils/display.py` (UI redesign v1.1.0), `README.md` |
| **Masalah** | Fitur email-auth & tech fingerprint belum ada di engine. |
| **Akar** | Permintaan KMC: perlu cek SPF/DKIM/DMARC dan fingerprint CMS/WAF per domain. |
| **Fix** | `email_auth.py`: `email_auth_check()` query SPF, DKIM (8 selector umum), DMARC paralel via `asyncio.gather`. Bug: dnspython wrap TXT values dalam `"..."` → `_clean_txt()` strip outer quotes sebelum cek tag `p=`. `tech_detect.py`: `detect_tech()` HTTP fetch sekali, fingerprint WAF/CDN/CMS/web server dari headers + body 8KB. Opsi 5 (full audit) kini 8 sub-check. |
| **Verifikasi** | Opsi 6 example.com → SPF `v=spf1 -all`, DKIM not found, DMARC `p=reject`, 2 warnings. Opsi 7 example.com → WAF Cloudflare, HTTP 200. |
| **Pelajaran** | dnspython `rdata.to_text()` untuk TXT records selalu wrap dengan double-quote — harus strip sebelum string matching tag seperti `p=` atau `v=spf1`.

### Fix #4 — Panel render crash: box="ROUNDED" string tidak valid di Rich
| | |
|---|---|
| **Tanggal** | 2026-11-02 |
| **File** | `utils/display.py` — `render_logo` |
| **Masalah** | `Panel(..., box="ROUNDED")` → `AttributeError: 'str' object has no attribute 'substitute'`. Rich menginterpretasikan `box` sebagai `Box` object, bukan string. |
| **Akar** | Rich `Panel.box` parameter tipe `Box \| None`, bukan `str`. Menulis `"ROUNDED"` membuat Rich memanggil `self.box.substitute()` di string → crash. |
| **Fix** | Import `ROUNDED` dari `rich.box`, ganti `box="ROUNDED"` → `box=ROUNDED`. |
| **Verifikasi** | `python main.py` menu → opsi 6 & 7 berjalan normal, logo panel ter-render dengan rounded border. |
| **Pelajaran** | Rich panel/box: selalu pakai objek dari `rich.box` (`ROUNDED`, `SQUARE`, `MINIMAL`, dsb.), bukan string name.
### Fix #3 — Ubah main.py dari flag-based CLI ke menu interaktif + perbaiki bug input
| | |
|---|---|
| **Tanggal** | 2026-10-31 |
| **File** | `main.py` (rewrite), `README.md` (update fitur & penggunaan) |
| **Masalah** | (1) Input non-angka di prompt option menyebabkan `ValueError` karena `int(raw)` di luar percabangan validasi. (2) `_return_to_menu` mengembalikan `None` lalu dipakai sebagai choice di dispatch — `dispatch[None]` KeyError. (3) Arsitektur flag-based (`--dns`, `--host`, dll) tidak ergonomis untuk pemakaian berulang. |
| **Akar** | Validasi `if raw.isdigit() and 0 <= int(raw) <= 5` hanya guard di dalam if; jalannya `return int(raw)` tetap dieksekusi untuk input non-angka seperti `abc` → `int("abc")` crash. `_return_to_menu()` tanpa return value → main loop menerima `None` sebagai choice → lookup `dispatch[None]` → KeyError. Desain flag: user harus hafal string flag untuk tiap subset, tidak cocok untuk pemakaian cepat. |
| **Fix** | Rewrite `main.py`: `show_main_menu()` pakai `while True` loop — validasi `isdigit()` + range check di satu tempat, non-angka → warning kuning, kosong → `continue`. `_return_to_menu()` menjadi `None` yang diabaikan di main loop (panggilan berdiri sendiri, bukan sebagai expression choice). Menu 6 pilihan (0–5), tiap pilihan panggil `_prompt_target()` lalu dispatch ke fungsi modul sesuai nomor. `run_full_audit` (pilihan 5) berurutan panggil 6 modul: `run_dns_records` → `run_dns_propagation` → `run_dns_backend` → `run_host_check` → `run_whois_ssl` → `run_security_scan`, masing-masing pakai `asyncio.run()` terpisah (fresh event loop, aman di CLI). |
| **Verifikasi** | Piped input test `1\nexample.com\n\n0` → DNS table tampil (A=172.66.147.243, NS=hera/elliott.cloudflare.com), kembali ke menu, exit clean. Test `3\nexample.com\n\n0` → host table tampil (TCP:80 open 65.5ms, HTTP 200, Server=cloudflare). Test `4\nexample.com\n\n0` → WHOIS (Registrar=IANA RESERVED, Created=1995-08-14) + TLS (Issuer=Unknown — CA store limitation di Windows, bukan bug) tampil. Input `abc` di prompt option → warning kuning, menu ulang, tidak crash. Input kosong di prompt target → "No target provided" → balik ke menu. |
| **Pelajaran** | `int(raw)` tetap dieksekusi untuk string non-angka tanpa guard terpisah — validasi dan eksekusi harus di dalam blok `if` yang sama. Return `None` dari fungsi yang dipanggil sebagai value di expression (bukan statement) akan mengalir ke caller; `_return_to_menu()` sebagai statement (bukan `choice = _return_to_menu()`) tidak beracun. |
### Fix #2 — Tambah modul --security: 9-check scanner port/path/header/TLS/WHOIS/AXFR
| | |
|---|---|
| **Tanggal** | 2026-10-31 |
| **File** | `core/security_check.py` (baru), `main.py` (flag + `run_security`), `README.md` (row + contoh) |
| **Masalah** | Tidak ada modul yang mendeteksi security exposure (port terbuka, path sensitif, header missing, TLS lemah, PII WHOIS, AXFR) — user meminta fitur ini ke KMC |
| **Akar** | KMC sebelumnya hanya memeriksa status (WHOIS/TLS/host/DNS), bukan security posture |
| **Fix** | Buat `core/security_check.py` dengan `SecurityFinding`/`SecurityReport` dataclass + 9 check async: exposed ports (10 port, reuse `host_ping._tcp_probe`), sensitive paths (10 path, httpx), version disclosure (regex Server/X-Powered-By), missing headers (6 header), cookie flags, CORS misconfig, WHOIS PII (email regex di `fetch_whois`), TLS lemah (TLSv1/1.1 handshake), AXFR zone transfer (`dns.query.send`). Setiap error per-check ditangani → INFO finding, tidak crash. `main.py` tambah `--security` flag + `run_security()` yang render rich Table (Check/Severity/Detail) + summary count. |
| **Verifikasi** | `python main.py example.com --security` → 0 CRITICAL, 2 HIGH (CSP+HSTS missing), 4 MEDIUM, 2 LOW, 4 INFO (AXFR refused, TLSv1 rejected, WHOIS PII redacted). `python main.py bagasbudi.my.id --security` → 0 CRITICAL, 2 HIGH, 3 MEDIUM (termasuk `/admin` HTTP 200 = Vercel next-admin), 4 LOW (wp-admin/wp-login 403), 6 INFO. Tidak ada crash. Bug `dns.query.Timeout` → `dns.exception.Timeout` sudah fix. |
| **Pelajaran** | `dns.exception.Timeout` bukan `dns.query.Timeout` — dnspython letak exception di `dns.exception`, bukan di modul query. Jangan asumsi lokasi exception dari nama modul. |
### Fix #1 — WHOIS registry hardcoded ke Verisign: domain non-.com gagal / hasil tidak relevan + Akar
| | |
|---|---|
| **Tanggal** | 2026-10-31 |
| **File** | `core/domain_whois.py` — `fetch_whois`, `_lookup_registry`, `TLD_REGISTRIES` |
| **Masalah** | `fetch_whois` hardcoded ke `whois.verisign-grs.com`; `google.co.id --whois` mengembalikan data Verisign yang tidak relevan, dan PANDI tidak akan menjawab di server Verisign |
| **Akar** | Tidak ada routing TLD-aware; semua query dikirim ke satu server Verisign yang hanya melayani .com/.net/.org |
| **Fix** | Tambahkan `TLD_REGISTRIES` dict (`.com`, `.net`, `.org`, `.info`, `.id`, `.co.id`, `.my`, `.co.th`, `.jp`, `.uk`, `.de`, `.au`, `.ca`, `.io`, `.dev`, `.app`, dll.) dan fungsi `_lookup_registry()` yang cek dua-level TLD (mis. `co.id`) sebelum satu-level; fallback tetap Verisign. Perbaiki juga hostname `.id` dari `whois.idnd.id` → `whois.pandi.id` (yang satu tidak resolve), dan `.co.th` dari `whois.th` → `whois.thnic.co.th`. |
| **Verifikasi** | `python main.py example.com` → registrar `RESERVED-Internet Assigned Numbers Authority`, created `1995-08-14`, nameservers Cloudflare, semua section tampil. `python main.py google.co.id --whois` → routing ke `whois.pandi.id` (resolve OK, timeout karena port 43 PANDI diblokir di jaringan ini — error ditangani, tidak crash). |
| **Pelajaran** | WHOIS registry bersifat TLD-specific; jangan hardcoded satu server. Gunakan lookup dua-level TLD (untuk `co.id`, `com.my`, dll.) dengan fallback ke satu-level. Selalu validasi hostname registry resolve sebelum commit. |
