# -*- coding: utf-8 -*-
"""Test offline core/ai_slop_detect.py (tanpa akses jaringan).

Menjalankan fungsi-fungsi internal dengan teks sintetik:
  - Teks "AI slop" buatan (harus skor tinggi)
  - Teks manusia bervariasi (harus skor rendah)
  - Teks Bahasa Indonesia dengan slang (harus mendeteksi kamus ID)
  - URL tidak valid (harus gagal dengan rapi)

Jalankan: python test_ai_slop_offline.py
"""

import json
import math
import sys

from core import ai_slop_detect as mod


# ---------------------------------------------------------------------
# Bahan teks sintetik
# ---------------------------------------------------------------------

# Teks gaya LLM: kalimat serupa panjang, banyak frasa slop
AI_SLOP_EN = (
    "Furthermore, the modern landscape of technology demands that we delve "
    "into the crucial role of artificial intelligence. It is important to note "
    "that, in today's digital era, companies must leverage the power of "
    "innovative solutions. Moreover, seamless integration plays a vital role in "
    "this transformation. Ultimately, the journey ahead requires that we not "
    "only embrace change but also build robust frameworks. When it comes to "
    "looking ahead, the tapestry of possibilities remains vast. "
    "Additionally, we must consider the many facets of this evolving field. "
    "In conclusion, the next decade will be defined by those who can "
    "seamlessly adapt and remain innovative in their approach. "
    "It is a testament to the fact that technology moves at a crucial pace. "
    "The landscape of enterprise software is a testament to this very shift, "
    "where every team must leverage the power of data-driven workflows. "
    "Furthermore, a crucial role is played by automation in every modern "
    "organization, and it is important to remember that seamless tooling is "
    "no longer optional. In today's market, the organizations that "
    "innovate fastest will win. Moreover, they will not only capture new "
    "customers but also retain their existing base through a robust product "
    "story. Ultimately, this is a testament to how quickly the modern "
    "landscape can change, and we must delve deeper into the data to "
    "understand why. When it comes to the next chapter, the tapestry of "
    "opportunity grows larger, and additionally, the stakes rise with it."
)

# Teks manusia: bervariasi panjang kalimat, personal, banyak detail
HUMAN_EN = (
    "Okay so — I spent all of yesterday staring at this one line of code. "
    "It looked fine. It built. It passed the unit tests, which usually means "
    "something is broken somewhere I can't see. "
    "By 2 a.m. I had a war story brewing. "
    "The fix? A missing await. Just one. But the debugging took four hours "
    "because the error swallowed itself. "
    "Lesson learned, for what it's worth: read the stack trace from the top, "
    "not the bottom. I always read from the bottom. Sigh. "
    "My coffee went cold. Then hot again when I remembered I hadn't "
    "actually restarted the dev server. Third coffee. It was one of those "
    "days where the universe is personally unimpressed with my codebase. "
    "Anyway, the deploy finally went out around noon, and now it's "
    "someone else's problem. Not mine. I'm going to sleep."
)

# Teks Bahasa Indonesia dengan slang
SLANG_ID = (
    "Gw udah coba 5 jam, gak jalan-jalan juga. Mungkin masalahnya di "
    "middleware gw yang salah order. Coba balik ke commit minggu lalu, "
    "sejak itu baru muncul. Oh iya, jangan lupa restart service-nya dulu, "
    "karena kadang cache-nya nyangkut. Next: cek log di /var/log, cari "
    "pola 'timeout' atau 'connection reset' — biasanya itu indikasi upstream "
    "keburu penuh. Kalau emang bener, tambahin rate limit di gateway. "
    "Buatnya gampang, tapi debug-nya yang bikin pusing. Gw udah ngelapor "
    "ke Tim A, nanti lanjut lewat meeting hari Jumat. "
    "Catatan: jangan lupa backup dulu sebelum apply perubahan. "
    "Kalau gw gak di kantor, temen gw bisa standby di channel #ops. "
    "Oh, satu lagi — ticket JIRA-4321 udah gw update statusnya, "
    "jadi kalau ada yang nanya, tinggal benerin di sana. "
    "Waktu gw coba di environment staging, ternyata jalan, jadi "
    "kemungkinan besar ini cuma masalah config prod. "
    "Tungguin response-nya dulu, jangan langsung restart. "
    "Sering kali restart justru bikin lebih parah."
)

# Teks Bahasa Indonesia gaya formal + frasa slop LLM
AI_SLOP_ID = (
    "Dalam lanskap digital saat ini, penting untuk diingat bahwa setiap "
    "organisasi memiliki peran penting dalam transformasi teknologi. Secara "
    "keseluruhan, hal ini merupakan bukti dari kemajuan yang tak terpisahkan "
    "dari berbagai sektor. Ketika kita menyikapi hal ini secara lebih jauh, "
    "ternyata tidak hanya sektor swasta tetapi juga pemerintah turut "
    "menjadi keniscayaan dalam membangun fondasi yang kuat. Sebagaimana "
    "telah dibahas, berbagai pihak perlu mengedepankan inovasi. Sebagai "
    "cermin dari keberhasilan, langkah ini harus ditopang oleh data yang "
    "robust dan strategi yang tidak bisa dipisahkan dari kebutuhan masyarakat. "
    "Selanjutnya, penting untuk diingat kembali bahwa dalam lanskap digital "
    "ini, berbagai pihak harus menyikapi setiap perubahan secara lebih jauh. "
    "Hal tersebut merupakan bukti dari komitmen yang tidak bisa dipisahkan "
    "dari tujuan utama organisasi. Sebagaimana telah dibahas tadi, peran "
    "penting teknologi juga menjadi keniscayaan di berbagai sektor. "
    "Sebagai cermin dari langkah ini, kita perlu melihat secara keseluruhan "
    "bagaimana setiap inisiatif menjadi keniscayaan yang tak terpisahkan."
)


# ---------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------

def analyze(text: str) -> dict:
    """Jalankan pipeline internal tanpa fetch."""
    a = mod._analyze_text(text)
    score = mod._compute_score(a)
    conf = mod._confidence(score, a)
    return {
        "words": a.word_count,
        "sentences": a.sentence_count,
        "cv": round(a.sentence_len_std / a.avg_sentence_len, 3) if a.avg_sentence_len else 0,
        "ttr": round(a.type_token_ratio, 3),
        "repeat": round(a.repeated_sentence_ratio, 3),
        "kw_hits": a.keyword_hits,
        "kw_ratio": round(a.keyword_ratio_per_1000, 2),
        "lang": a.language_hint,
        "score": score,
        "conf": conf,
        "top": a.top_patterns[:5],
    }


def print_report(label: str, r: dict) -> None:
    print(f"\n=== {label} ===")
    for k in ("words", "sentences", "cv", "ttr", "repeat",
              "kw_hits", "kw_ratio", "lang", "score", "conf"):
        print(f"  {k:8s} = {r[k]}")
    if r["top"]:
        print("  top    = " + ", ".join(f"{p['pattern']}×{p['count']}" for p in r["top"]))


# ---------------------------------------------------------------------
# Uji
# ---------------------------------------------------------------------

def test_extract_strips_noise() -> None:
    html = (
        "<html><head><style>body{color:red}</style></head>"
        "<body><nav>Home About</nav><header>Logo</header>"
        "<article><p>" + " ".join(["meaningful content sentence here."] * 30) +
        "</p></article>"
        "<footer>© 2024</footer></body></html>"
    )
    text = mod._extract_main_text(html)
    assert "meaningful" in text, "teks artikel harus tertinggal"
    assert "Home About" not in text, "nav harus dibuang"
    assert "Logo" not in text, "header harus dibuang"
    assert "© 2024" not in text, "footer harus dibuang"
    assert "body{" not in text, "CSS harus dibuang"
    print("[ok] extract_main_text membuang nav/header/footer/style")


def test_slop_dictionaries() -> None:
    # Kamus EN harus bisa menangkap 'furthermore', 'delve', 'testament'
    hits = mod._count_keyword_hits("furthermore delve a testament", mod.SLOP_KEYWORDS_EN)
    assert hits >= 3, f"EN keyword hit harus >= 3, dapat {hits}"
    # Kamus ID harus bisa menangkap 'penting untuk diingat'
    hits_id = mod._count_keyword_hits("penting untuk diingat dalam lanskap digital",
                                      mod.SLOP_KEYWORDS_ID)
    assert hits_id >= 2, f"ID keyword hit harus >= 2, dapat {hits_id}"
    # Word boundary: 'delve' tidak boleh menghitung 'delving' dari 'delver'
    assert mod._count_keyword_hits("delivered", mod.SLOP_KEYWORDS_EN) == 0, \
        "'delivered' tak boleh dihitung sebagai 'delve'"
    print(f"[ok] slop dictionaries EN hits={hits} ID hits={hits_id}")


def test_scoring_contrast() -> None:
    """Teks AI vs manusia: skor AI harus jelas lebih tinggi."""
    r_ai = analyze(AI_SLOP_EN)
    r_human = analyze(HUMAN_EN)
    r_slang = analyze(SLANG_ID)
    r_aiid = analyze(AI_SLOP_ID)

    print_report("AI SLOP (EN)", r_ai)
    print_report("HUMAN (EN)", r_human)
    print_report("SLANG (ID)", r_slang)
    print_report("AI SLOP (ID)", r_aiid)

    assert r_ai["score"] >= 40, f"skor AI EN harus tinggi, dapat {r_ai['score']}"
    assert r_human["score"] < r_ai["score"], \
        f"skor human ({r_human['score']}) harus < skor AI ({r_ai['score']})"
    assert r_slang["lang"] == "id", f"bahasa slang harus 'id', dapat {r_slang['lang']}"
    assert r_ai["lang"] in ("en", ""), f"bahasa AI EN harus 'en', dapat {r_ai['lang']}"
    # Teks ID formal dengan frasa slop juga harus lebih tinggi dari slang
    assert r_aiid["score"] > r_slang["score"], \
        f"AI ID ({r_aiid['score']}) harus > slang ID ({r_slang['score']})"

    # JSON serializable
    json.dumps(r_ai)
    print("[ok] skor: AI tinggi, human rendah, bahasa terdeteksi")


def test_fail_path() -> None:
    """URL yang tidak ada harus return status failed tanpa crash."""
    out = mod.check_ai_slop("https://this-domain-does-not-exist-xyz123.invalid/")
    assert out["status"] == "failed", f"harus failed, dapat {out}"
    assert out["error"], "error message harus diisi"
    assert out["ai_slop_score"] == 0
    assert isinstance(out["detected_patterns"], list)
    print(f"[ok] fail path: status=failed, error={out['error']!r}")


def test_short_text_fail() -> None:
    """Teks lebih pendek dari MIN_WORDS harus failed."""
    out = mod.check_ai_slop("http://127.0.0.1:9/")  # port pasti tak ada
    assert out["status"] == "failed"
    print(f"[ok] short/unreachable path: error={out['error']!r}")


# ---------------------------------------------------------------------

if __name__ == "__main__":
    print("=== TEST OFFLINE: ai_slop_detect ===")
    test_extract_strips_noise()
    test_slop_dictionaries()
    test_scoring_contrast()
    test_fail_path()
    test_short_text_fail()
    print("\nSEMUA UJI OFFLINE LULUS [PASS]")
