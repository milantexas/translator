"""Downloads Argos language models on first start (needs internet once)."""
import os
if os.getenv("BACKEND", "argos").lower() != "argos":
    raise SystemExit(0)

import argostranslate.package as pkg
from argostranslate import translate

langs = {c.strip() for c in os.getenv("LANGS", "en,es,fr,de,it,pt").split(",") if c.strip()}
installed = translate.get_installed_languages()
have = {(l.code, tr.to_lang.code) for l in installed for tr in l.translations_from}

pkg.update_package_index()
for p in pkg.get_available_packages():
    # Only pairs that touch English; other pairs pivot through English automatically.
    if p.from_code in langs and p.to_code in langs and "en" in (p.from_code, p.to_code):
        if (p.from_code, p.to_code) not in have:
            print(f"Installing {p.from_code}->{p.to_code}", flush=True)
            pkg.install_from_path(p.download())
print("Models ready.")
