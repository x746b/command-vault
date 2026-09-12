"""Build normalized CyberGym bundles from an existing offline dataset."""

import argparse
import json
from pathlib import Path

from command_vault.adapters.cybergym import CyberGymAdapter


def build_bundles(dataset: str | Path, revision: str, output: str | Path) -> dict:
    """Return aggregate counts without source content, paths, or bundle inventories."""
    report = CyberGymAdapter(dataset, revision).build(output)
    return {
        'records_seen': report.records_seen,
        'records_selected': report.records_selected,
        'artifacts': report.artifacts,
        'redactions_by_type': dict(report.redactions_by_type),
        'bundle_count': len(report.bundles),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', type=Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    report = build_bundles(args.dataset, args.revision, args.output)
    print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))


if __name__ == '__main__':
    main()
