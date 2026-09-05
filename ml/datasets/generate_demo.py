"""Generate a clearly labeled DEMO dataset for development.

This is synthetic. It is not a production threat-intel feed.
Do not present demo accuracy as real-world production accuracy.
"""

from __future__ import annotations

import csv
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "demo_urls.csv"

LEGIT = [
    "https://www.wikipedia.org/wiki/Phishing",
    "https://www.google.com/search?q=weather",
    "https://github.com/about",
    "https://www.microsoft.com/en-in",
    "https://www.apple.com/in/",
    "https://www.amazon.in/gp/help/customer/display.html",
    "https://www.paypal.com/in/home",
    "https://www.netflix.com/in/",
    "https://www.instagram.com/",
    "https://www.facebook.com/help",
    "https://www.whatsapp.com/",
    "https://www.hdfcbank.com/",
    "https://www.icicibank.com/",
    "https://www.axisbank.com/",
    "https://www.rbi.org.in/",
    "https://uidai.gov.in/",
    "https://www.irctc.co.in/nget/train-search",
    "https://www.indiapost.gov.in/",
    "https://www.incometax.gov.in/",
    "https://www.mygov.in/",
    "https://npci.org.in/",
    "https://www.linkedin.com/",
    "https://en.wikipedia.org/wiki/Main_Page",
    "https://developer.mozilla.org/en-US/docs/Web/Security",
    "https://www.nist.gov/cybersecurity",
    "https://www.cisa.gov/topics/cybersecurity-best-practices",
    "https://www.cloudflare.com/learning/access-management/what-is-phishing/",
    "https://www.bbc.com/news",
    "https://www.nytimes.com/",
    "https://stackoverflow.com/questions",
    "https://www.reddit.com/r/cybersecurity/",
    "https://gitlab.com/explore",
    "https://bitbucket.org/product",
    "https://www.dropbox.com/",
    "https://www.adobe.com/",
    "https://www.spotify.com/",
    "https://www.airbnb.com/",
    "https://www.uber.com/",
    "https://www.booking.com/",
    "https://www.khanacademy.org/",
    "https://www.coursera.org/",
    "https://mit.edu/",
    "https://www.stanford.edu/",
    "https://www.iitb.ac.in/",
    "https://www.who.int/",
    "https://www.un.org/",
    "https://www.gov.uk/",
    "https://www.india.gov.in/",
    "https://play.google.com/store",
    "https://support.apple.com/",
]

SUSPICIOUS = [
    "http://news-update.example.com/read",
    "https://bit.ly/demo-shortener-sample",
    "https://tinyurl.com/demo-sample",
    "https://secure-update.example.net/notice",
    "https://login.help.support.example.org/info",
    "http://files.example.com:8080/download",
    "https://account-review.example.com/status",
    "https://promo-rewards.example.xyz/offer",
    "https://verify-device.example.com/check",
    "https://www.example.com/login/help/reset",
    "http://docs.example.org/very/long/path/to/resource/page?ref=newsletter&utm=1",
    "https://support-center.example.top/ticket",
    "https://my-account.example.work/profile",
    "https://wallet-notice.example.com/info",
    "https://kyc-update.example.net/form",
    "https://free-gift.example.com/claim",
    "https://urgent-notice.example.org/read",
    "https://www.example.com/%6c%6f%67%69%6e",
    "https://sub.sub.help.example.com/",
    "http://example.com/signin",
]

PHISH = [
    "https://secure-paypal-login.example.xyz/verify/account",
    "https://paypal.login.verify.account.example.com/secure",
    "http://192.0.2.80/login",
    "https://paypa1.com/signin",
    "https://g00gle-security.com/verify",
    "https://pay-pal-login.com/account",
    "https://apple-icloud-verify.example.tk/unlock",
    "https://hdfcbank-secure-login.example.gq/otp",
    "https://microsoft-online-verify.example.ml/auth",
    "https://whatsapp-support.example.cf/restore",
    "https://sbi-onlinesbi.example.xyz/netbanking",
    "https://uidai-aadhaar-update.example.top/kyc",
    "https://irctc-ticket.example.xyz/refund",
    "https://netflix-billing.example.icu/update",
    "https://amazon-account-verify.example.click/signin",
    "http://203.0.113.25/paypal/login",
    "https://login.paypa1-secure.example/verify",
    "https://xn--pypal-4ve.com/login",
    "https://facebook-security.example.xyz/confirm",
    "https://instagram-prize.example.win/claim",
    "https://axisbank-otp.example.loan/verify",
    "https://icici-netbanking.example.xyz/login",
    "https://google.secure-login.example.com/password",
    "https://appleid-unlock.example.xyz/recover",
    "https://user:passwd@paypal.com.example.xyz/login",
    "https://www.paypa1-alerts.com/account/update",
    "https://office365-login.example.rest/auth",
    "https://rbi-kyc.example.xyz/pan",
    "https://phonepe-wallet-refund.example.icu/upi",
    "https://dropbox-shared.example.gq/signin",
]


def mutate_legit(url: str, rng: random.Random) -> str:
    extras = ["", "/", "/about", "/help", "?utm_source=demo", "/en-us"]
    return url.rstrip("/") + rng.choice(extras)


def mutate_phish(rng: random.Random) -> str:
    brands = ["paypal", "google", "apple", "amazon", "microsoft", "hdfc", "sbi", "netflix", "whatsapp"]
    tlds = ["xyz", "top", "gq", "tk", "icu", "click", "win"]
    paths = ["/login", "/verify/account", "/signin", "/secure/otp", "/update-payment", "/kyc"]
    brand = rng.choice(brands)
    return f"https://{brand}-{rng.choice(['login','secure','verify','alert'])}.{rng.choice(['example','secure-mail','auth-page'])}.{rng.choice(tlds)}{rng.choice(paths)}"


def mutate_sus(rng: random.Random) -> str:
    hosts = ["example.com", "example.net", "example.org"]
    words = ["update", "notice", "support", "help", "device"]
    return f"https://{rng.choice(words)}.{rng.choice(hosts)}/{rng.choice(words)}"


def generate(n_legit: int = 220, n_sus: int = 160, n_phish: int = 220) -> list[tuple[str, int]]:
    rng = random.Random(42)
    rows: list[tuple[str, int]] = []
    for i in range(n_legit):
        rows.append((mutate_legit(LEGIT[i % len(LEGIT)], rng), 0))
    for i in range(n_sus):
        if i < len(SUSPICIOUS):
            rows.append((SUSPICIOUS[i], 1))
        else:
            rows.append((mutate_sus(rng), 1))
    for i in range(n_phish):
        if i < len(PHISH):
            rows.append((PHISH[i], 2))
        else:
            rows.append((mutate_phish(rng), 2))
    rng.shuffle(rows)
    return rows


def main() -> None:
    rows = generate()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["url", "label"])
        writer.writerows(rows)
    dist = {0: 0, 1: 0, 2: 0}
    for _, y in rows:
        dist[y] += 1
    print(f"Wrote {len(rows)} rows to {OUT}")
    print(f"Class distribution (0 legit, 1 suspicious, 2 phishing): {dist}")


if __name__ == "__main__":
    main()
