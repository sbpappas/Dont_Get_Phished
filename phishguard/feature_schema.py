"""Canonical feature schema shared by training and inference.

Every name here is a column in the public phishing dataset (Vrbancic et al.,
"Datasets for phishing websites detection", Data in Brief, 2020) that the ML
model is trained on. Keeping training and live inference locked to the same
ordered list is what makes the two consistent -- change this list and you
must retrain the model (`scripts/train_model.py`).
"""

FEATURE_ORDER = [
    # --- URL-level lexical features (no network needed) ---
    "qty_dot_url",
    "qty_hyphen_url",
    "qty_underline_url",
    "qty_slash_url",
    "qty_questionmark_url",
    "qty_equal_url",
    "qty_at_url",
    "qty_and_url",
    "qty_exclamation_url",
    "qty_tilde_url",
    "qty_tld_url",
    "length_url",
    # --- Domain-level lexical features ---
    "qty_dot_domain",
    "qty_hyphen_domain",
    "qty_underline_domain",
    "qty_vowels_domain",
    "domain_length",
    "domain_in_ip",
    "server_client_domain",
    # --- Path (directory/file) lexical features ---
    "qty_dot_directory",
    "qty_hyphen_directory",
    "qty_slash_directory",
    "directory_length",
    "file_length",
    # --- Query string lexical features ---
    "qty_params",
    "tld_present_params",
    "params_length",
    # --- Other lexical signals ---
    "email_in_url",
    "url_shortened",
    # --- Live network / host features (require internet access) ---
    "time_response",
    "domain_spf",
    "time_domain_activation",
    "time_domain_expiration",
    "qty_ip_resolved",
    "qty_nameservers",
    "qty_mx_servers",
    "ttl_hostname",
    "tls_ssl_certificate",
    "qty_redirects",
]

LABEL_COLUMN = "phishing"

# Sentinel used throughout the codebase (and in the source dataset) for
# "could not be determined" -- e.g. WHOIS lookup timed out, DNS query failed.
UNKNOWN = -1
