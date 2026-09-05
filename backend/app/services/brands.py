"""Configurable brand dictionary. Brand keywords never auto-classify phishing."""

from __future__ import annotations

BRANDS: list[dict] = [
    {"name": "Google", "keywords": ["google", "gmail", "youtube", "gstatic"], "domains": ["google.com", "gmail.com", "youtube.com", "google.co.in"]},
    {"name": "Microsoft", "keywords": ["microsoft", "outlook", "office365", "onedrive", "azure"], "domains": ["microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"]},
    {"name": "Apple", "keywords": ["apple", "icloud", "appstore"], "domains": ["apple.com", "icloud.com"]},
    {"name": "Amazon", "keywords": ["amazon", "aws", "kindle"], "domains": ["amazon.com", "amazon.in", "aws.amazon.com"]},
    {"name": "PayPal", "keywords": ["paypal", "pay-pal"], "domains": ["paypal.com", "paypal.me"]},
    {"name": "Netflix", "keywords": ["netflix"], "domains": ["netflix.com"]},
    {"name": "Instagram", "keywords": ["instagram", "insta"], "domains": ["instagram.com"]},
    {"name": "Facebook", "keywords": ["facebook", "fb", "meta"], "domains": ["facebook.com", "fb.com", "meta.com"]},
    {"name": "WhatsApp", "keywords": ["whatsapp", "whats-app"], "domains": ["whatsapp.com", "whatsapp.net"]},
    {"name": "SBI", "keywords": ["sbi", "onlinesbi", "sbibank"], "domains": ["onlinesbi.sbi", "sbi.co.in", "sbi.bank.in"]},
    {"name": "HDFC", "keywords": ["hdfc", "hdfcbank"], "domains": ["hdfcbank.com", "hdfc.com"]},
    {"name": "ICICI", "keywords": ["icici", "icicibank"], "domains": ["icicibank.com"]},
    {"name": "Axis", "keywords": ["axisbank", "axis"], "domains": ["axisbank.com"]},
    {"name": "RBI", "keywords": ["rbi", "reservebank"], "domains": ["rbi.org.in"]},
    {"name": "UIDAI", "keywords": ["uidai", "aadhaar", "aadhar"], "domains": ["uidai.gov.in"]},
    {"name": "IRCTC", "keywords": ["irctc"], "domains": ["irctc.co.in"]},
    {"name": "India Post", "keywords": ["indiapost", "indianpost"], "domains": ["indiapost.gov.in"]},
    {"name": "Income Tax India", "keywords": ["incometax", "incometaxindia"], "domains": ["incometax.gov.in"]},
    {"name": "MyGov", "keywords": ["mygov"], "domains": ["mygov.in"]},
    {"name": "NPCI / UPI", "keywords": ["npci", "upi", "bhim"], "domains": ["npci.org.in", "upi.org.in"]},
    {"name": "LinkedIn", "keywords": ["linkedin"], "domains": ["linkedin.com"]},
    {"name": "Twitter / X", "keywords": ["twitter", "x.com"], "domains": ["twitter.com", "x.com"]},
    {"name": "GitHub", "keywords": ["github"], "domains": ["github.com", "github.io"]},
    {"name": "Dropbox", "keywords": ["dropbox"], "domains": ["dropbox.com"]},
    {"name": "Adobe", "keywords": ["adobe"], "domains": ["adobe.com"]},
    {"name": "Paytm", "keywords": ["paytm"], "domains": ["paytm.com"]},
    {"name": "PhonePe", "keywords": ["phonepe"], "domains": ["phonepe.com"]},
    {"name": "Flipkart", "keywords": ["flipkart"], "domains": ["flipkart.com"]},
]

UNTRUSTED_TLDS = {
    "xyz", "top", "gq", "tk", "ml", "cf", "ga", "work", "click", "country",
    "stream", "gdn", "mom", "xin", "loan", "download", "racing", "jetzt",
    "win", "review", "vip", "icu", "rest", "surf", "date",
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc",
    "rb.gy", "s.id",
}

KEYWORD_GROUPS: dict[str, list[str]] = {
    "login": ["login", "log-in", "signin", "sign-in", "signon", "authenticate", "authentication", "password", "credential", "passwd"],
    "verify": ["verify", "verification", "confirm", "confirmation", "validate"],
    "account": ["account", "acct", "profile", "userid"],
    "payment": ["payment", "pay", "invoice", "billing", "checkout", "refund", "transaction", "card", "cvv"],
    "security": ["security", "secure", "locked", "unlock", "protect"],
    "update": ["update", "upgrade", "renew", "reactivate"],
    "bank": ["bank", "banking", "sbi", "hdfc", "icici", "axis", "wallet", "upi"],
    "free": ["free", "bonus", "prize", "gift", "reward", "winner"],
    "reward": ["reward", "rewards", "cashback", "coupon"],
    "wallet": ["wallet", "crypto", "metamask", "seedphrase"],
    "otp": ["otp", "2fa", "one-time", "onetime", "pin"],
    "urgency": ["suspended", "urgent", "expire", "expired", "immediate", "warning", "blocked", "limited", "unusual"],
    "government": ["tax", "challan", "rto", "kyc", "aadhaar", "aadhar", "pan", "subsidy", "uidai", "passport"],
}

CONFUSABLE_MAP = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "8": "b",
        "@": "a",
        "$": "s",
        "!": "i",
    }
)
