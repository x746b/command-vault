"""Create a complete, offline ExploitGym-enriched CyberGym collection."""

import argparse
import json
from pathlib import Path

from command_vault.adapters.cybergym_enrichment import CyberGymEnrichmentAdapter


def enrich_bundles(bundles: str | Path, metadata: str | Path, revision: str, output: str | Path) -> dict:
    """Return aggregate-only counts; never expose paths, record IDs, or source text."""
    report = CyberGymEnrichmentAdapter(bundles, metadata, revision).build(output)
    return {
        'bundle_count': report.bundle_count, 'enriched': report.enriched, 'unmatched': report.unmatched,
        'class_filled': report.class_filled, 'sanitizer_filled': report.sanitizer_filled,
        'architecture_filled': report.architecture_filled, 'mitigation_links': report.mitigation_links,
        'redactions_by_type': dict(report.redactions_by_type),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundles', type=Path, required=True)
    parser.add_argument('--metadata', type=Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    result = enrich_bundles(args.bundles, args.metadata, args.revision, args.output)
    print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))


if __name__ == '__main__':
    main()
