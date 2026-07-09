"""luci_sky.dedup — collapse duplicate findings before reporting."""
from __future__ import annotations

import re
from typing import Dict, List, Tuple

from luci_sky.models import Finding

_WS = re.compile(r"\s+")


def _norm_title(title: str) -> str:
    return _WS.sub(" ", title.strip().lower())


def _keys(f: Finding) -> List[Tuple[str, str]]:
    """Grouping keys for a finding: one per CVE id (else the normalized title)."""
    url = f.affected_url
    if f.cve_ids:
        return [(cve, url) for cve in f.cve_ids]
    return [(_norm_title(f.title), url)]


def _rank(f: Finding) -> tuple:
    conf_rank = {"high": 3, "medium": 2, "low": 1}.get(f.confidence.value, 0)
    return (f.severity.numeric_rank, f.cvss_score, conf_rank)


def merge_findings(findings: List[Finding]) -> List[Finding]:
    """Merge findings sharing a CVE id (else normalized title) + affected URL.

    NOTE: the winning Finding in each multi-member group is mutated in place
    (references/cve_ids/evidence/contributing_checks). Callers that need to keep
    the originals should pass copies. Safe in the scanner, which builds findings
    fresh per run and merges once before reporting.
    """
    groups: Dict[Tuple[str, str], List[Finding]] = {}   # key -> shared bucket
    order: List[List[Finding]] = []                      # buckets, first-seen order
    for f in findings:
        keys = _keys(f)
        bucket = None
        for k in keys:
            if k in groups:
                bucket = groups[k]
                break
        if bucket is None:
            bucket = []
            order.append(bucket)
        bucket.append(f)
        for k in keys:                # alias ALL keys so any shared key merges
            groups.setdefault(k, bucket)

    merged: List[Finding] = []
    for members in order:
        if len(members) == 1:
            merged.append(members[0])
            continue
        best = max(members, key=_rank)
        refs, cves, checks, evidence = [], [], [], []
        for m in members:
            refs.extend(m.references)
            cves.extend(m.cve_ids)
            checks.append(m.check_id)
            evidence.append(f"[{m.check_id}] {m.evidence}")
        best.references = sorted(dict.fromkeys(refs))
        best.cve_ids = sorted(dict.fromkeys(cves))
        best.contributing_checks = sorted(dict.fromkeys(checks))
        best.evidence = "\n---\n".join(evidence)
        merged.append(best)
    return merged
