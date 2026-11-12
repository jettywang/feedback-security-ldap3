#!/usr/bin/env python3
"""Entry point: build certs if needed and run all EXTERNAL contract scenarios."""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from scenarios import run_all
from report import print_report


def ensure_pki():
    if not os.path.exists(os.path.join(HERE, 'pki', 'client.crt')):
        subprocess.check_call([os.path.join(HERE, 'make_certs.sh')])


def main():
    ensure_pki()
    records = run_all()
    print_report(records)
    failures = [r for r in records if r['outcome'] == 'unexpected_error']
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
