# Instruksi Proyek (adaVIBE)

Berkas ini dibaca mesin tiap sesi. Ringkas dengan sengaja — instruksi panjang
justru diabaikan.

## Memori perbaikan — CHANGELOG_FIXES.md
SEBELUM memperbaiki bug: cari riwayatnya dulu (jangan baca seluruh file).
```
grep -n -i "<gejala|komponen>" CHANGELOG_FIXES.md
```
Banyak bug adalah regresi/kembaran fix lama — akarnya sudah tercatat. Sebutkan
temuan itu sebelum mulai.

SESUDAH fix TERBUKTI bekerja: sisipkan entri TEPAT di bawah baris
`<!-- ENTRI BARU DI BAWAH BARIS INI -->` (terbaru paling atas). Dengan Edit:
old_string = baris penanda itu saja, new_string = baris penanda + entri baru.
JANGAN menjangkar pada judul entri lain — entri lama bisa tertimpa. Nomor =
nomor tertinggi yang ada + 1. Format: `### Fix #N — Judul: Gejala + Akar`, lalu
Tanggal · File · Masalah · Akar · Fix · Verifikasi · Pelajaran. Hanya tulis yang
sudah terverifikasi (ada bukti); sertakan angka nyata, bukan klaim umum. Fix yang
ternyata menimbulkan regresi → entri BARU yang menyebut nomor penyebabnya.
Tulis catatan dengan alat edit (Edit / apply_patch), BUKAN perintah/skrip shell
(Set-Content/Out-File/skrip PowerShell atau Python) — penyandian & akhir baris rusak;
jangan tinggalkan skrip bantu di repo.

## Serah-terima — handoffs/
Satu berkas `handoffs/<topik>.md` per pekerjaan yang MELEWATI batas sesi; fix
kecil yang selesai langsung ke changelog, tanpa handoff. Awal sesi: baca handoff
yang cocok dengan tugas. Tulis rencana/daftar tugas ke berkas SAAT disusun, lalu
perbarui (timpa, jangan menumpuk) tiap satu langkah tuntas. Selesai &
terverifikasi → pastikan entri changelog ada, lalu HAPUS berkas handoff-nya
(handoff = pekerjaan menggantung, bukan arsip). Ditunda → `Status: DITUNDA` +
langkah berikutnya yang jelas.

## Memori proyek — docs/
Memori mesin TIDAK tersimpan di luar folder ini: yang perlu diingat sesi berikutnya
harus ditulis ke berkas proyek. Pengetahuan yang sudah tuntas (analisa, riset,
keputusan arsitektur, cara kerja yang ditemukan) → `docs/<topik>.md`, bukan handoff.
Jadi: CHANGELOG_FIXES = perbaikan terverifikasi · handoffs/ = pekerjaan menggantung ·
docs/ = pengetahuan selesai.

## Sumber pengetahuan — adaRAG & adaBROWSER
Butuh dokumen bisnis, aturan, atau panduan pihak ketiga (API pembayaran, regulasi)?
Bila alat adaRAG tersedia, `rag_cari` dulu — gudang dokumen milik pemilik akun.
Hasil kosong/tak relevan BUKAN alasan berhenti: lanjut ke berkas proyek, lalu
adaBROWSER (`web_cari` / `web_baca`) untuk sumber RESMI terbaru, dan sebutkan sumbernya.
JANGAN `rag_catat` untuk catatan ngoding — catatan itu dibaca bot balas-chat
pelanggan; pelajaran ngoding tetap di CHANGELOG_FIXES.md / docs/.

## Kebiasaan
- Jalankan test sebelum menyatakan selesai.
- Jangan jalankan perintah perusak (rm -rf, DROP, migrate:fresh, force-push)
  tanpa konfirmasi eksplisit.
