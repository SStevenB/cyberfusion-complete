# data_collection/news_collector.py
# Fetches security news from public RSS feeds.
# No API key required. Uses feedparser library.

import json
import os
import feedparser
from datetime import datetime, timezone
from typing import List, Dict, Any

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")

RSS_FEEDS = [
    {"url": "https://feeds.feedburner.com/TheHackersNews",        "source": "The Hacker News"},
    {"url": "https://www.bleepingcomputer.com/feed/",             "source": "BleepingComputer"},
    {"url": "https://krebsonsecurity.com/feed/",                  "source": "Krebs on Security"},
    {"url": "https://www.darkreading.com/rss.xml",                "source": "Dark Reading"},
    {"url": "https://feeds.feedburner.com/securityweek",          "source": "SecurityWeek"},
]

PRIORITY_KEYWORDS = [
    "ransomware", "zero-day", "0-day", "critical", "exploit", "breach",
    "vulnerability", "rce", "remote code", "patch", "cve", "backdoor",
    "malware", "phishing", "credential", "data leak", "supply chain",
]


def _is_priority(title: str, summary: str) -> bool:
    text = (title + " " + summary).lower()
    return any(kw in text for kw in PRIORITY_KEYWORDS)


def _matched_keywords(title: str, summary: str) -> List[str]:
    text = (title + " " + summary).lower()
    return [kw for kw in PRIORITY_KEYWORDS if kw in text]


def fetch_security_news(max_per_feed: int = 10) -> List[Dict[str, Any]]:
    items = []
    for feed_info in RSS_FEEDS:
        try:
            feed = feedparser.parse(feed_info["url"])
            for entry in feed.entries[:max_per_feed]:
                title   = entry.get("title", "")
                summary = entry.get("summary", "")
                link    = entry.get("link", "")
                pub     = entry.get("published", "")

                items.append({
                    "source":            feed_info["source"],
                    "title":             title,
                    "summary":           summary[:500],
                    "link":              link,
                    "published":         pub,
                    "is_priority":       _is_priority(title, summary),
                    "priority_keywords": _matched_keywords(title, summary),
                })
            print(f"[News Collector] {feed_info['source']}: {len(feed.entries[:max_per_feed])} items")
        except Exception as e:
            print(f"[News Collector] Failed to fetch {feed_info['source']}: {e}")

    print(f"[News Collector] Total: {len(items)} news items")
    return items


def save_news(items: List[Dict[str, Any]]) -> str:
    os.makedirs(RAW_DIR, exist_ok=True)
    out = os.path.join(RAW_DIR, "threat_news.json")
    with open(out, "w") as f:
        json.dump({
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "total": len(items),
            "items": items,
        }, f, indent=2)
    print(f"[News Collector] Saved {len(items)} items → {out}")
    return out


if __name__ == "__main__":
    news = fetch_security_news(max_per_feed=5)
    save_news(news)
