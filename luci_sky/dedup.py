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
    """Merge findings sharing a CVE id (else normalized title) + affected URL."""
    groups: Dict[Tuple[str, str], List[Finding]] = {}
    order: List[Tuple[str, str]] = []
    for f in findings:
        # A finding joins the first existing group any of its keys already map to.
        chosen = None
        for k in _keys(f):
            if k in groups:
                chosen = k
                break
        if chosen is None:
            chosen = _keys(f)[0]
            groups[chosen] = []
            order.append(chosen)
        groups[chosen].append(f)

    merged: List[Finding] = []
    for k in order:
        members = groups[k]
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
