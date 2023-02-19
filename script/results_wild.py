import os
import json
import re
import sys
from collections import defaultdict
from datetime import timedelta

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))
TOOLS = ['mythril', 'slither', 'oyente', 'osiris', 'smartcheck', 'maian', 'securify', 'honeybadger']
# TOOLS = ['mythril', 'slither', 'oyente', 'osiris', 'smartcheck', 'manticore', 'maian', 'securify', 'honeybadger']
# get the first argv
VULNERABILITIES_FILE = sys.argv[1]

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

with open(os.path.join(ROOT, 'metadata', 'vulnerabilities_mapping.csv')) as fd:
    header = fd.readline().strip().split(',')
    for line in fd:
        v = line.strip().split(',')
        index = -1
        if 'TRUE' in v:
            index = v.index('TRUE')
        elif 'MAYBE' in v:
            index = v.index('MAYBE')
        if index > -1:
            vulnerability_mapping[v[1]] = header[index]

categories = sorted(list(set(vulnerability_mapping.values())))
categories.remove('Ignore')
categories.remove('Other')
categories.append('Other')

print('===== vulnerability_mapping =====')
print(vulnerability_mapping)

vulnerability_fd = open(os.path.join(ROOT, 'metadata', 'vulnerabilities.csv'), 'w', encoding='utf-8')

# def add_vul(contract, tool, vulnerability, line):
#     original_vulnerability = vulnerability
#     vulnerability = vulnerability.strip().lower().title().replace('_', ' ').replace('.', '').replace('Solidity ', '').replace('Potentially ', '')
#     vulnerability = re.sub(r' At Instruction .*', '', vulnerability)

#     category = vulnerability_mapping.get(original_vulnerability, 'unknown')
#     if category == 'unknown' or category == 'Ignore':
#         return
#     vulnerability_stat[vulnerability] += 1
#     tool_stat[tool][vulnerability] += 1
#     contract_vulnerabilities[contract].add(vulnerability)

#     output[contract]['nb_vulnerabilities'] += 1
#     if line is not None and line > 0:
#         output[contract]['lines'].add(line)
#     output[contract]['tools'][tool]['vulnerabilities'].setdefault(original_vulnerability, 0)
#     output[contract]['tools'][tool]['vulnerabilities'][original_vulnerability] += 1
#     output[contract]['tools'][tool]['categories'].setdefault(category, 0)
#     output[contract]['tools'][tool]['categories'][category] += 1

#     tool_category_stat[tool][category].add(contract)

# with open(os.path.join(ROOT, 'metadata', 'unique_contracts.csv')) as ufd:
#     for line in ufd:
#         contract = line.split(',')[0]
#         if contract not in output:
#             output[contract] = {'tools': defaultdict(lambda: {'vulnerabilities': defaultdict(int), 'categories': defaultdict(int)}), 'lines': set(), 'nb_vulnerabilities': 0}
#         for tool in TOOLS:
#             path_result = os.path.join('results', tool, output_name, contract, 'result.json')
#             if not os.path.exists(path_result):
#                 continue
#             with open(path_result, 'r', encoding='utf-8') as fd:
#                 try:
#                     data = json.load(fd)
#                 except Exception:
#                     continue
#                 duration_stat[tool] += data.get('duration', 0)
#                 count[tool] += 1
#                 total_duration += data.get('duration',
