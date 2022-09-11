import sys
import os
from stix2.v21 import (Indicator, Malware, Relationship, Bundle, DomainName)


if __name__ == "__main__":
    if os.path.isfile("cytrox.stix2"):
        os.remove("cytrox.stix2")

    with open("config_profiles.txt") as f:
        configs = list({a.strip() for a in f.read().split()})


    with open("domains.txt") as f:
        domains = list({a.strip() for a in f.read().split()})

    with open("file_paths.txt") as f:
        filepaths = list({a.strip() for a in f.read().split()})

    malware = Malware(name="Predator", is_family=False, description="IOCs for Cytrox Predator")
    res = [malware]
    for d in domains:
        i = Indicator(
            indicator_types=["malicious-activity"],
            pattern=f"[domain-name:value='{d}']",
            pattern_type="stix",
        )

        res.extend((i, Relationship(i, 'indicates', malware)))
    for f in filepaths:
        i = Indicator(
            indicator_types=["malicious-activity"],
            pattern=f"[file:path='{f}']",
            pattern_type="stix",
        )

        res.extend((i, Relationship(i, 'indicates', malware)))
    for c in configs:
        i = Indicator(
            indicator_types=["malicious-activity"],
            pattern=f"[configuration-profile:id='{c}']",
            pattern_type="stix",
        )

        res.extend((i, Relationship(i, 'indicates', malware)))
    bundle = Bundle(objects=res)
    with open("cytrox.stix2", "w+") as f:
        f.write(str(bundle))
    print("cytrox.stix2 file created")
