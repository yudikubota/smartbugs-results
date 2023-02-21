import os
import json
import re
import sys
import csv
from collections import defaultdict
from datetime import timedelta

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))
TOOLS = ['mythril', 'slither', 'oyente', 'osiris', 'smartcheck', 'maian', 'securify', 'honeybadger']
# TOOLS = ['mythril', 'slither', 'oyente', 'osiris', 'smartcheck', 'manticore', 'maian', 'securify', 'honeybadger']
# get the first argv
# VULNERABILITIES_FILE = sys.argv[1]

output_name = 'first_run'
vulnerability_stat = defaultdict(int)
tool_stat = defaultdict(lambda: defaultdict(int))
tool_category_stat = defaultdict(lambda: defaultdict(set))
duration_stat = defaultdict(int)
total_duration = 0
count = defaultdict(int)
output = {}
contract_vulnerabilities = defaultdict(set)

vulnerability_mapping = {}

with open(os.path.join(ROOT, 'metadata', 'swc_to_dasp.json')) as fd:
    swc_to_dasp = json.load(fd)

CSV_HEADERS = ['tool', 'vuln', 'swc', 'dasp', 'ignore', 'severity']
with open(os.path.join(ROOT, 'metadata', 'vulnerabilities_mapping_new.csv')) as fd:
    csvreader = csv.reader(fd)

    # skip the header
    csvreader.__next__()

    # process lines
    for row in csvreader:
        v = {}
        for header, value in zip(CSV_HEADERS, row):
            v[header] = value

        if (v['ignore'] == 'true'):
            continue

        vulnerability_mapping[v['vuln']] = int(v['dasp']) if v['dasp'] != '' else int(swc_to_dasp[v['swc']]) if v['swc'] != '' else 'unknown'

categories = sorted(list(set(vulnerability_mapping.values())))

print('===== vulnerability_mapping =====')
print(vulnerability_mapping)
print(categories)

vulnerability_fd = open(os.path.join(ROOT, 'metadata', 'vulnerabilities.csv'), 'w', encoding='utf-8')