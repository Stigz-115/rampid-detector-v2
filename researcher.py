"""
Web research module for finding public evidence of LiveRamp partnerships.

Supports two search backends:
  1. **DuckDuckGo** – free, no API key required (uses duckduckgo-search library).
  2. **Google Custom Search** – requires a Google API key and Custom Search Engine ID.

Searches for press releases, news articles, case studies, and public documentation
mentioning the prospect company alongside LiveRamp / RampID.
"""

import re
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Search query templates
# ---------------------------------------------------------------------------

SEARCH_QUERIES = [
    "{company} LiveRamp",
    "{company} RampID",
    "{company} LiveRamp partnership",
    "{company} LiveRamp press release",
    "{company} LiveRamp case study",
    "{company} identity resolution LiveRamp",
]

# Keywords that strengthen partnership evidence
PARTNERSHIP_INDICATORS = [
    "partnership", "partner", "integration", "integrate", "integrated",
    "powered by", "using", "adopts", "adopted", "implements", "implemented",
    "launches", "announces", "selected", "chooses", "deploys", "deployed",
    "collaboration", "collaborate", "case study", "customer story",
    "rampid", "identity graph", "identity resolution", "data onboarding",
    "authenticated traffic solution", "ats",
]

# Keywords that weaken partnership evidence (non-partnership mentions)
WEAK_INDICATORS = [
    "competitor", "versus", "vs", "compared to", "alternative to",
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SearchResult:
    """A single web search result."""
    title: str
    url: str
    snippet: str
    source: str = ""                # Which search engine found this
    relevance_score: float = 0.0    # 0.0 to 1.0
    indicators: list[str] = field(default_factory=list)


@dataclass
class ResearchReport:
    """Aggregated research findings for a company."""
    company: str = ""
    search_engine: str = ""
    results: list[SearchResult] = field(default_factory=list)
    summary: str = ""
    confidence: str = "Unknown"     # "High", "Medium", "Low", "None"
    error: Optional[str] = None

    @property
    def result_count(self) -> int:
        return len(self.results)

    @property
    def high_confidence_results(self) -> list[SearchResult]:
        """Results with relevance score >= 0.5."""
        return [r for r in self.results if r.relevance_score >= 0.5]


# ---------------------------------------------------------------------------
# Relevance scoring
# ---------------------------------------------------------------------------

def score_result(result: SearchResult, company: str) -> tuple[float, list[str]]:
    """
    Score a search result for relevance to a LiveRamp partnership.

    Returns (score, indicators_found).
    """
    text = f"{result.title} {result.snippet}".lower()
    company_lower = company.lower()
    indicators = []
    score = 0.0

    # Company name present
    if company_lower in text:
        score += 0.3
        indicators.append("company name mentioned")

    # LiveRamp / RampID present
    liveramp_terms = ["liveramp", "rampid", "ramp id", "rlcdn"]
    liveramp_found = [t for t in liveramp_terms if t in text]
    if liveramp_found:
        score += 0.3
        indicators.append(f"LiveRamp terms: {', '.join(liveramp_found)}")

    # Partnership indicators
    partnership_found = [kw for kw in PARTNERSHIP_INDICATORS if kw in text]
    if partnership_found:
        score += 0.2
        indicators.append(f"partnership keywords: {', '.join(partnership_found[:3])}")

    # Press release / official announcement signals
    official_signals = ["press release", "announces", "pr newswire", "business wire",
                        "newsroom", "official", "launch"]
    official_found = [kw for kw in official_signals if kw in text]
    if official_found:
        score += 0.1
        indicators.append(f"official announcement signals")

    # Weak indicators reduce score
    weak_found = [kw for kw in WEAK_INDICATORS if kw in text]
    if weak_found:
        score -= 0.15
        indicators.append(f"weak/competitor context: {', '.join(weak_found[:2])}")

    # Cap score at 1.0
    score = min(max(score, 0.0), 1.0)

    return score, indicators


# ---------------------------------------------------------------------------
# DuckDuckGo search
# ---------------------------------------------------------------------------

def search_duckduckgo(company: str, max_results: int = 20) -> ResearchReport:
    """
    Search DuckDuckGo for evidence of LiveRamp partnership.

    No API key required.
    """
    from ddgs import DDGS

    report = ResearchReport(company=company, search_engine="DuckDuckGo")
    all_results: dict[str, SearchResult] = {}  # URL -> result (dedupe)

    for query_template in SEARCH_QUERIES:
        query = query_template.format(company=company)
        try:
            with DDGS() as ddgs:
                results = list(ddgs.text(query, max_results=max_results // len(SEARCH_QUERIES) + 2))
        except Exception as e:
            report.error = f"DuckDuckGo search error: {e}"
            continue

        for r in results:
            url = r.get("href") or r.get("url") or ""
            title = r.get("title", "")
            snippet = r.get("body") or r.get("snippet", "")

            if not url or url in all_results:
                continue

            sr = SearchResult(
                title=title,
                url=url,
                snippet=snippet,
                source="DuckDuckGo",
            )
            sr.relevance_score, sr.indicators = score_result(sr, company)
            all_results[url] = sr

    # Sort by relevance score
    report.results = sorted(all_results.values(), key=lambda x: x.relevance_score, reverse=True)

    _compute_summary(report)
    return report


# ---------------------------------------------------------------------------
# Google Custom Search
# ---------------------------------------------------------------------------

def search_google(company: str, api_key: str, cx_id: str, max_results: int = 20) -> ResearchReport:
    """
    Search Google Custom Search API for evidence of LiveRamp partnership.

    Requires:
        - api_key: Google API key with Custom Search API enabled
        - cx_id: Custom Search Engine ID
    """
    import requests as req

    report = ResearchReport(company=company, search_engine="Google Custom Search")
    all_results: dict[str, SearchResult] = {}

    for query_template in SEARCH_QUERIES:
        query = query_template.format(company=company)
        try:
            params = {
                "key": api_key,
                "cx": cx_id,
                "q": query,
                "num": min(10, max_results),
            }
            resp = req.get("https://www.googleapis.com/customsearch/v1", params=params, timeout=15)

            if resp.status_code != 200:
                if not report.error:
                    report.error = f"Google API error ({resp.status_code}): {resp.text[:200]}"
                continue

            data = resp.json()
            for item in data.get("items", []):
                url = item.get("link", "")
                title = item.get("title", "")
                snippet = item.get("snippet", "")

                if not url or url in all_results:
                    continue

                sr = SearchResult(
                    title=title,
                    url=url,
                    snippet=snippet,
                    source="Google",
                )
                sr.relevance_score, sr.indicators = score_result(sr, company)
                all_results[url] = sr

        except Exception as e:
            if not report.error:
                report.error = f"Google search error: {e}"
            continue

    report.results = sorted(all_results.values(), key=lambda x: x.relevance_score, reverse=True)
    _compute_summary(report)
    return report


# ---------------------------------------------------------------------------
# Summary computation
# ---------------------------------------------------------------------------

def _compute_summary(report: ResearchReport):
    """Compute confidence level and summary text for a research report."""
    if report.error and not report.results:
        report.confidence = "Error"
        report.summary = f"Search failed: {report.error}"
        return

    if not report.results:
        report.confidence = "None"
        report.summary = (
            f"No public results found mentioning '{report.company}' alongside LiveRamp/RampID. "
            "This may indicate no public partnership exists, or the company uses a different name in public materials."
        )
        return

    high_conf = report.high_confidence_results

    if len(high_conf) >= 5:
        report.confidence = "High"
    elif len(high_conf) >= 2:
        report.confidence = "Medium"
    elif len(high_conf) >= 1:
        report.confidence = "Low"
    else:
        report.confidence = "None"

    report.summary = (
        f"Found {len(report.results)} result(s) for '{report.company}' + LiveRamp/RampID. "
        f"{len(high_conf)} high-relevance result(s). "
        f"Partnership evidence: {report.confidence}."
    )
