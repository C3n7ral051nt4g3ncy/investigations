import sys
import os
from stix2.v21 import (Indicator, Malware, Relationship, Bundle, DomainName)


if __name__ == "__main__":
    if os.path.isfile("pegasus.stix2"):
        os.remove("pegasus.stix2")

    with open("domains.txt") as f:
        domains = list({a.strip() for a in f.read().split()})

    with open("files.txt") as f:
        filenames = list({a.strip() for a in f.read().split()})

    with open("processes.txt") as f:
        processes = list({a.strip() for a in f.read().split()})

    with open("emails.txt") as f:
        emails = list({a.strip() for a in f.read().split()})

    malware = Malware(name="Pegasus", is_family=False, description="IOCs for Pegasus")
    res = [malware]
    for d in domains:
        i = Indicator(
            indicator_types=["malicious-activity"],
            pattern=f"[domain-name:value='{d}']",
            pattern_type="stix",
        )

        res.extend((i, Relationship(i, 'indicates', malware)))
    for p in processes:
        i = Indicator(
            indicator_types=["malicious-activity"],
            pattern=f"[process:name='{p}']",
            pattern_type="stix",
        )

        res.extend((i, Relationship(i, 'indicates', malware)))
    for f in filenames:
        i = Indicator(
            indicator_types=["malicious-activity"],
            pattern=f"[file:name='{f}']",
            pattern_type="stix",
        )

        res.extend((i, Relationship(i, 'indicates', malware)))
    for e in emails:
        i = Indicator(
            indicator_types=["malicious-activity"],
            pattern=f"[email-addr:value='{e}']",
            pattern_type="stix",
        )

        res.extend((i, Relationship(i, 'indicates', malware)))
    bundle = Bundle(objects=res)
    with open("pegasus.stix2", "w+") as f:
        f.write(str(bundle))
    print("pegasus.stix2 file created")
