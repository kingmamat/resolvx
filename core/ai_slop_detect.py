"""AI slop / AI content detector untuk konten web.

Mengambil teks utama dari sebuah URL, lalu menganalisisnya dengan metode
hybrid statistik + kamus kata kunci:

1. Perplexity / burstiness — variasi panjang kalimat, keragaman kosakata,
   dan kemunculan pola kalimat yang berulang persis. Teks buatan LLM
   cenderung seragam: panjang kalimat monoton, kosakata repetitif.
2. Slop keywords — kamus frasa transisi yang sangat sering muncul di teks
   LLM (EN + ID), dihitung rasionya terhadap total teks.

Hasil dikembalikan sebagai dict yang siap di-`json.dumps` — kompatibel
langsung dengan framework web (Flask/FastAPI).

Dependensi: requests, beautifulsoup4
"""

from __future__ import annotations

import json
import math
import re
import string
from dataclasses import dataclass, field
from statistics import pstdev
from typing import Any

import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Konstanta analisis
# ---------------------------------------------------------------------------

# Skor minimum teks (dalam kata) agar deteksi dianggap valid.
# Teks lebih pendek dari ini tidak cukup data untuk analisis statistik.
MIN_WORDS: int = 100

# Skor ambang untuk menetapkan confidence level.
CONFIDENCE_HIGH_MIN: float = 65.0
CONFIDENCE_MID_MIN: float = 35.0

# Berat masing-masing sub-skor dalam penjumlahan akhir (total = 1.0).
WEIGHT_KEYWORDS: float = 0.40
WEIGHT_BURSTINESS: float = 0.25
WEIGHT_UNIFORMITY: float = 0.15
WEIGHT_REPETITION: float = 0.20

# Rasio keyword slop per 1000 kata yang dianggap indikasi kuat (saturasi).
KEYWORD_RATIO_SATURATION: float = 2.0

# Elemen HTML yang dibuang sebelum mengekstrak teks artikel.
_NOISE_TAGS = ("script", "style", "noscript", "template", "iframe",
               "nav", "header", "footer", "aside", "form", "button")

# Container prioritas saat mengambil teks utama artikel.
_CONTENT_SELECTORS = ("article", "main", "[itemprop='articleBody']",
                      "section p", "div p")


# ---------------------------------------------------------------------------
# Kamus kata kunci slop
# ---------------------------------------------------------------------------
# Frasa yang frekuensinya jauh lebih tinggi di teks LLM dibanding teks
# manusia biasa. Dicari dengan case-insensitive; untuk kata tunggal dipakai
# word boundary agar tidak menghitung kecocokan di dalam kata lain
# (mis. "game" tidak boleh dihitung dari "garage").

SLOP_KEYWORDS_EN: dict[str, str] = {
    # Kata LLM-preferred
    r"\bdelve\b": r"delve",
    r"\bdelves\b": r"delve",
    r"\bdelving\b": r"delve",
    r"\btestament\b": r"testament",
    r"\bcrucial\b": r"crucial",
    r"\bleverage\b": r"leverage",
    r"\bleveraging\b": r"leverage",
    r"\bseamless\b": r"seamless",
    r"\bseamlessly\b": r"seamless",
    r"\brobust\b": r"robust",
    r"\binnovative\b": r"innovative",
    r"\bmuchmore\b": r"much more",
    # Metafora "tapestry" & sejenis
    r"\btapestry\b": r"tapestry",
    r"\bleverage the power of\b": r"leverage the power of",
    r"\bunlock the power of\b": r"unlock the power of",
    r"\bgame[- ]changer\b": r"game-changer",
    r"\blandscape\b(?=\sof\b)": r"landscape of",
    # Konstruksi transisi formal
    r"\bfurthermore\b": r"furthermore",
    r"\bmoreover\b": r"moreover",
    r"\badditionally\b": r"additionally",
    r"\bin conclusion\b": r"in conclusion",
    r"\bultimately\b": r"ultimately",
    r"\bnot only\b(?=\s+\w+\s+but also\b)": r"not only ... but also",
    r"\bin today'?s \w+\b": r"in today's X",
    r"\bwhen it comes to\b": r"when it comes to",
    r"\bit is important to (?:note|remember|consider)\b": r"it is important to ...",
    r"\bplays? a (?:crucial|vital|key|pivotal|significant) role\b": r"plays a crucial role",
    r"\bbuilt[- ]?on\b": r"built on",
    r"\blooking ahead\b": r"looking ahead",
}

SLOP_KEYWORDS_ID: dict[str, str] = {
    r"\bpenting untuk diingat\b": r"penting untuk diingat",
    r"\bperlu dicatat\b": r"perlu dicatat",
    r"\bdalam lanskap digital\b": r"dalam lanskap digital",
    r"\bmerupakan (?:bukti|tanda|cermin|pembuktian) (?:dari|tentang|bahwa)\b": r"merupakan bukti dari",
    r"\bsecara keseluruhan\b": r"secara keseluruhan",
    r"\bsimaknya lebih lanjut\b": r"simak lebih lanjut",
    r"\bmenyikapi hal ini\b": r"menyikapi hal ini",
    r"\bdi era digital\b": r"di era digital",
    r"\bperan penting\b": r"peran penting",
    r"\byang tidak bisa dipisahkan\b": r"tidak bisa dipisahkan",
    r"\btidak hanya .* tetapi juga\b": r"tidak hanya ... tetapi juga",
    r"\bsecara lebih jauh\b": r"secara lebih jauh",
    r"\bsebagai (?:bukti|penanda|cermin) dari\b": r"sebagai bukti dari",
    r"\bmenjadi (?:wajah|tuntutan|keniscayaan|keharusan) di\b": r"menjadi keniscayaan",
    r"\bsebagaimana telah dibahas\b": r"sebagaimana telah dibahas",
    r"\bberbagai pihak\b": r"berbagai pihak",
}


# ---------------------------------------------------------------------------
# Struktur data
# ---------------------------------------------------------------------------

@dataclass
class SlopAnalysis:
    """Hasil analisis linguistik untuk satu teks."""

    word_count: int = 0
    sentence_count: int = 0
    # Statistik panjang kalimat
    avg_sentence_len: float = 0.0
    sentence_len_std: float = 0.0
    # Keragaman kosakata
    type_token_ratio: float = 0.0
    # Perulangan kalimat
    repeated_sentence_ratio: float = 0.0
    # Kamus
    en_hits: int = 0
    id_hits: int = 0
    top_patterns: list[dict[str, Any]] = field(default_factory=list)

    @property
    def keyword_hits(self) -> int:
        return self.en_hits + self.id_hits

    @property
    def keyword_ratio_per_1000(self) -> float:
        """Jumlah kemunculan keyword slop per 1000 kata."""
        if self.word_count == 0:
            return 0.0
        return self.keyword_hits * 1000.0 / self.word_count


@dataclass
class AISlopReport:
    """Laporan akhir AI slop detection untuk satu URL."""

    status: str = "success"
    url: str = ""
    ai_slop_score: int = 0
    confidence_level: str = "Low"
    detected_patterns: list[dict[str, Any]] = field(default_factory=list)
    word_count: int = 0
    language_hint: str = ""
    error: str = ""


# ---------------------------------------------------------------------------
# Ekstraksi konten
# ---------------------------------------------------------------------------

def _extract_main_text(html: str) -> str:
    """Bersihkan HTML menjadi teks artikel murni (tanpa nav/header/footer)."""
    soup = BeautifulSoup(html, "html.parser")

    # Buang elemen sampah
    for tag in soup.find_all(_NOISE_TAGS):
        tag.decompose()

    # Coba container konten utama dulu, fallback ke seluruh body
    container = None
    for selector in _CONTENT_SELECTORS:
        container = soup.select_one(selector)
        if container:
            break
    if container is None:
        container = soup.body or soup

    # Ambil paragraf & heading agar struktur kalimat utuh
    parts: list[str] = []
    for el in container.find_all(["p", "h1", "h2", "h3", "h4", "li", "blockquote"]):
        text = el.get_text(separator=" ", strip=True)
        if len(text.split()) >= 3:  # abaikan label/button pendek
            parts.append(text)

    # Gabung, bersihkan spasi ganda
    raw = " ".join(parts)
    return re.sub(r"[ \t]+", " ", raw).strip()


def _split_sentences(text: str) -> list[str]:
    """Pecah teks menjadi kalimat (regex sederhana, cukup untuk deteksi)."""
    # Ganti entitas HTML yang tersisa
    text = re.sub(r"&[a-zA-Z]+;", " ", text)
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    return [s.strip() for s in sentences if len(s.strip()) >= 3]


def _count_keyword_hits(text_lower: str, patterns: dict[str, str]) -> int:
    """Hitung total kemunculan seluruh pola kamus di teks."""
    return sum(len(re.findall(pat, text_lower)) for pat in patterns)


def _find_top_patterns(text_lower: str,
                       patterns: dict[str, str],
                       limit: int = 8) -> list[dict[str, Any]]:
    """Pola slop dengan kemunculan terbanyak, urut menurun."""
    counts = [(label, len(re.findall(pat, text_lower)))
              for pat, label in patterns.items()]
    counts = [(label, n) for label, n in counts if n > 0]
    counts.sort(key=lambda x: x[1], reverse=True)
    return [{"pattern": label, "count": n} for label, n in counts[:limit]]


# ---------------------------------------------------------------------------
# Analisis
# ---------------------------------------------------------------------------

def _analyze_text(text: str) -> SlopAnalysis:
    """Jalankan analisis linguistik + kamus ke satu teks."""
    analysis = SlopAnalysis()
    words = re.findall(r"\b\w+\b", text)
    analysis.word_count = len(words)

    if analysis.word_count == 0:
        return analysis

    # --- Burstiness / variasi panjang kalimat ---
    sentences = _split_sentences(text)
    analysis.sentence_count = len(sentences)
    if sentences:
        lengths = [len(s.split()) for s in sentences]
        analysis.avg_sentence_len = sum(lengths) / len(lengths)
        analysis.sentence_len_std = pstdev(lengths) if len(lengths) > 1 else 0.0

    # --- Type-token ratio (keragaman kosakata) ---
    unique = len(set(w.lower() for w in words))
    analysis.type_token_ratio = unique / analysis.word_count

    # --- Perulangan kalimat ---
    if sentences:
        seen: dict[str, int] = {}
        for s in sentences:
            key = s.lower()
            seen[key] = seen.get(key, 0) + 1
        repeated = sum(n - 1 for n in seen.values() if n > 1)
        analysis.repeated_sentence_ratio = repeated / len(sentences)

    # --- Kamus slop ---
    text_lower = text.lower()
    analysis.en_hits = _count_keyword_hits(text_lower, SLOP_KEYWORDS_EN)
    analysis.id_hits = _count_keyword_hits(text_lower, SLOP_KEYWORDS_ID)

    # --- Deteksi bahasa secara heuristik ---
    ind_words = len(re.findall(r"\b(?:dan|yang|untuk|adalah|dengan|dari|ini|saya|kami|dapat|bisa)\b",
                               text_lower))
    eng_words = len(re.findall(r"\b(?:the|and|for|with|that|this|will|have|are|was)\b",
                               text_lower))
    analysis.top_patterns = _find_top_patterns(
        text_lower,
        {**SLOP_KEYWORDS_EN, **SLOP_KEYWORDS_ID},
        limit=10,
    )
    # Hint bahasa — hanya untuk konteks, tak memengaruhi skor
    if ind_words > eng_words:
        analysis.language_hint = "id"
    elif eng_words > ind_words:
        analysis.language_hint = "en"

    return analysis


def _compute_score(a: SlopAnalysis) -> int:
    """Gabung sub-skor menjadi 0-100."""
    if a.word_count < MIN_WORDS:
        return 0

    # 1) Skor keyword (0..1) — saturasi di KEYWORD_RATIO_SATURATION per 1000 kata
    kw = min(a.keyword_ratio_per_1000 / KEYWORD_RATIO_SATURATION, 1.0)

    # 2) Skor burstiness rendah (0..1).
    #    Koefisien variasi kecil = panjang kalimat seragam = indikasi AI.
    cv = (a.sentence_len_std / a.avg_sentence_len) if a.avg_sentence_len else 0.0
    # Human teks umumnya CV 0.4-0.8; AI sering < 0.25.
    burst = max(0.0, min(1.0, (0.6 - cv) / 0.6)) if cv < 0.6 else 0.0

    # 3) Skor uniformitas TTR rendah (0..1).
    #    TTR rendah = kosakata repetitif = indikasi AI.
    #    Human TTR 0.3-0.5; AI sering < 0.25.
    uni = max(0.0, min(1.0, (0.45 - a.type_token_ratio) / 0.45)) \
        if a.type_token_ratio < 0.45 else 0.0

    # 4) Skor perulangan kalimat (0..1) — saturasi di 20%
    rep = min(a.repeated_sentence_ratio / 0.20, 1.0)

    total = (WEIGHT_KEYWORDS * kw + WEIGHT_BURSTINESS * burst +
             WEIGHT_UNIFORMITY * uni + WEIGHT_REPETITION * rep)
    return int(round(total * 100))


def _confidence(score: int, a: SlopAnalysis) -> str:
    """Tetapkan tingkat keyakinan berdasarkan skor & jumlah data."""
    if a.word_count < MIN_WORDS:
        return "Low"
    if score >= CONFIDENCE_HIGH_MIN:
        return "High"
    if score >= CONFIDENCE_MID_MIN:
        return "Medium"
    return "Low"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def check_ai_slop(url: str, timeout: int = 15) -> dict[str, Any]:
    """Periksa satu URL untuk indikasi AI slop. Mengembalikan dict JSON-safe.

    Alur:
      1. Fetch HTML (requests, UA browser).
      2. Ekstrak teks utama (BeautifulSoup).
      3. Analisis linguistik + kamus slop.
      4. Hitung skor 0-100, confidence, dan pola teratas.

    Selalu mengembalikan dict dengan kunci:
      status, url, ai_slop_score, confidence_level, detected_patterns,
      word_count, language_hint, error.
    """
    report = AISlopReport(url=url)

    # --- Fetch ---
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (KMC-RESOLVX/1.0)"},
            allow_redirects=True,
        )
        resp.raise_for_status()
    except requests.exceptions.SSLError as exc:
        report.status = "failed"
        report.error = f"SSL error: {exc.__class__.__name__}"
        return report.__dict__
    except requests.exceptions.ConnectionError as exc:
        report.status = "failed"
        report.error = f"Connection error: {exc.__class__.__name__}"
        return report.__dict__
    except requests.exceptions.Timeout as exc:
        report.status = "failed"
        report.error = f"Timeout: {exc.__class__.__name__}"
        return report.__dict__
    except requests.exceptions.HTTPError as exc:
        report.status = "failed"
        report.error = f"HTTP {resp.status_code}" if 'resp' in dir() else f"HTTP error: {exc}"
        return report.__dict__
    except requests.exceptions.RequestException as exc:
        report.status = "failed"
        report.error = f"{exc.__class__.__name__}: {exc}"
        return report.__dict__

    # --- Ekstrak teks ---
    try:
        text = _extract_main_text(resp.text)
    except Exception as exc:
        report.status = "failed"
        report.error = f"Parse error: {exc.__class__.__name__}"
        return report.__dict__

    if not text or len(text.split()) < MIN_WORDS:
        report.status = "failed"
        report.error = f"Text too short ({len(text.split())} words, need {MIN_WORDS})"
        return report.__dict__

    # --- Analisis ---
    analysis = _analyze_text(text)
    report.word_count = analysis.word_count
    report.language_hint = analysis.language_hint
    report.ai_slop_score = _compute_score(analysis)
    report.confidence_level = _confidence(report.ai_slop_score, analysis)
    report.detected_patterns = analysis.top_patterns

    return report.__dict__


def check_ai_slop_json(url: str, timeout: int = 15) -> str:
    """Versi yang langsung return string JSON (nyaman buat log/curl)."""
    return json.dumps(check_ai_slop(url, timeout=timeout), ensure_ascii=False, indent=2)
