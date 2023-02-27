import sys
import csv
import json
import traceback
import os

# get the first arg as the input csv
ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))
# INPUT_CSV_FILE = os.path.join(ROOT, 'first-run.csv')
# OUTPUT_JSON_FILE = os.path.join(ROOT, 'metadata', 'first-run.json')
INPUT_CSV_FILE = sys.argv[1]
OUTPUT_JSON_FILE = sys.argv[2]

# confuzzius
# conkas
# maian
# manticore-0.3.7
# mythril-0.23.15
# mythril-0.23.5
# osiris
# oyente
# securify
# slither
# smartcheck
# solhint-3.3.8
# solhint

IGNORED_TOOLS = ['solhint', 'smartcheck', 'securify', 'manticore-0.3.7', 'osiris', 'mythril-0.23.5', 'solhint-3.3.8']
# IGNORED_TOOLS = ['solhint', 'smartcheck', 'securify', 'manticore-0.3.7', 'osiris']
# IGNORED_TOOLS = (sys.argv[3] if len(sys.argv) > 3 else '').split(',')
CSV_HEADERS = [
    'filename',
    'basename',
    'toolid',
    'toolmode',
    'parser_version',
    'runid',
    'start',
    'duration',
    'exit_code',
    'findings',
    'infos',
    'errors',
    'fails',
]
SHOULD_PRINT = False

csv.field_size_limit(sys.maxsize)

# results
results_by_tool = {}

# ----------------

with open(os.path.join(ROOT, 'metadata', 'swc_to_dasp.json')) as fd:
    swc_to_dasp = json.load(fd)

dasp_mapping = {}
with open(os.path.join(ROOT, 'metadata', 'dasp.json')) as fd:
    dasp_mapping = json.load(fd)

VULN_CSV_HEADERS = ['tool', 'vuln', 'swc', 'dasp', 'ignore', 'severity']
vulnerability_mapping = {}
with open(os.path.join(ROOT, 'metadata', 'vulnerabilities_mapping_new.csv')) as fd:
    csvreader = csv.reader(fd)

    # skip the header
    csvreader.__next__()

    # process lines
    for row in csvreader:
        v = {}
        for header, value in zip(VULN_CSV_HEADERS, row):
            v[header] = value
        
        v['vuln'] = v['vuln'].strip().replace('-', '_')

        if (v['ignore'] == 'Sim'):
            vulnerability_mapping[v['vuln']] = 'Ignore'
            continue

        if (not v['dasp']):
            raise Exception(f'vulnerability {v["vuln"]} has no dasp mapping')

        vulnerability_mapping[v['vuln']] = v['dasp']

# ----------------

unmapped_list = set()
total_timeouts = 0

def logger(msg):
    if SHOULD_PRINT:
        print(msg)

logger(f'dasp_mapping {dasp_mapping}')
logger(f'vulnerability_mapping {vulnerability_mapping}')

def init_tool_results(toolid):
    global results_by_tool
    if (not results_by_tool.get(toolid, None)):
        results_by_tool[toolid] = {}
        tool_results = results_by_tool[toolid]
        tool_results['total_duration'] = 0
        tool_results['n_analysis'] = 0
        tool_results['n_findings'] = 0
        tool_results['n_sucessful'] = 0
        tool_results['findings'] = {}
        # tool_results['q_findings_per_category'] = {}
        tool_results['cat_per_contract'] = {}
        tool_results['n_errors'] = 0
        tool_results['errors'] = {}
        tool_results['n_fails'] = 0
        tool_results['n_timeouts'] = 0
        tool_results['fails'] = {}
        tool_results['infos'] = {}
        tool_results['findings_per_contract'] = {}

    return results_by_tool[toolid]

def process_row(line):
    global results_by_tool, total_timeouts

    v = {}
    for header, value in zip(CSV_HEADERS, line):
        v[header] = value
    toolid = v['toolid']
    contract_address = v['basename']

    if (toolid in IGNORED_TOOLS):
        return

    logger(f"processing {v['basename']} {toolid}...")

    tool_results = init_tool_results(toolid)

    tool_results['total_duration'] += float(v['duration'])
    tool_results['n_analysis'] += 1

    this_contract_categories = tool_results['cat_per_contract'].get(contract_address, set())
    this_contract_findings = tool_results['findings_per_contract'].get(contract_address, set())
    v['findings'] = [f.strip() for f in v['findings'].split(',') if f.strip() != '']
    v['errors']   = [f.strip() for f in v['errors'].split(',') if f.strip() != '']
    v['infos']    = [f.strip() for f in v['infos'].split(',') if f.strip() != '']
    v['fails']    = [f.strip() for f in v['fails'].split(',') if f.strip() != '']

    for finding in v['findings']:
        vm = vulnerability_mapping.get(finding, 'Unmapped')
        if (vm == 'Unmapped'):
            unmapped_list.add(f'{toolid},{finding}')
        category = dasp_mapping[vm]

        logger(f'{contract_address} {toolid} / finding -> category : {finding} -> {category} / this_contract_categories: {this_contract_categories} / this_contract_findings: {this_contract_findings}')

        if (category == 'Ignore'):
            continue

        this_contract_findings.add(finding)
        this_contract_categories.add(category)

        tool_results['n_findings'] += 1
        tool_results['findings'][finding] = tool_results['findings'].get(finding, 0) + 1

    for info in v['infos']:
        tool_results['infos'][info] = tool_results['infos'].get(info, 0) + 1

    tool_results['n_errors'] += len(v['errors'])
    for error in v['errors']:
        tool_results['errors'][error] = tool_results['errors'].get(error, 0) + 1

    timeouts = 1 if 'DOCKER_TIMEOUT' in v['fails'] else 0
    total_timeouts += timeouts
    row_fails = len(v['fails'])

    tool_results['n_fails'] += row_fails
    tool_results['n_timeouts'] += timeouts
    tool_results['n_sucessful'] += 1 if row_fails == 0 else 0

    tool_results['cat_per_contract'][contract_address] = this_contract_categories
    tool_results['findings_per_contract'][contract_address] = this_contract_findings

# MAIN | read the csv file line by line
with open(INPUT_CSV_FILE, 'r') as fp:
    csvreader = csv.reader(fp)

    # skip the header
    csvreader.__next__()

    # process lines
    row_counter = 0
    for row in csvreader:
        try:
            row_counter += 1
            if (row_counter % 10000 == 0):
                print(f"")
                print(f"Row counter: {row_counter}")
            process_row(row)
        except Exception as e:
            print(f"Error: {e}")
            traceback.print_tb(e.__traceback__)
            print(f"Row: {row}")

total_analysis = 0
total_duration = 0
total_findings = 0
total_errors = 0
total_fails = 0
total_sucessful = 0

# vulns_per_contract = {}
cat_per_contract = {}
# vulns_per_category = {}

for toolid in results_by_tool:
    tool_results = results_by_tool[toolid]

    # average_duration_per_tool
    tool_results['avg_duration'] = tool_results['total_duration'] / tool_results['n_analysis']

    # totals
    total_duration += tool_results['total_duration']
    total_findings += tool_results['n_findings']
    total_errors += tool_results['n_errors']
    total_fails += tool_results['n_fails']
    total_sucessful += tool_results['n_sucessful']
    total_analysis += tool_results['n_analysis']

    # other data
    tool_results['timeout_percentage'] = tool_results['n_timeouts'] / tool_results['n_analysis'] * 100
    tool_results['success_percentage'] = tool_results['n_sucessful'] / tool_results['n_analysis'] * 100
    contracts_with_vuln = 0

    tool_results['q_contract_per_cat'] = {}
    for contract, cats in tool_results['cat_per_contract'].items():
        cat_per_contract[contract] = cat_per_contract.get(contract, set())

        should_count = any([c != 'Ignore' for c in cats])
        if (should_count):
            contracts_with_vuln += 1

        for cat in cats:
            tool_results['q_contract_per_cat'][cat] = tool_results['q_contract_per_cat'].get(cat, 0) + 1
            cat_per_contract[contract].add(cat)

    tool_results['contracts_with_vuln'] = contracts_with_vuln
    if (tool_results['n_analysis']):
        tool_results['contracts_with_vuln_percentage'] = contracts_with_vuln / tool_results['n_analysis'] * 100
    else:
        tool_results['contracts_with_vuln_percentage'] = 0

    # vuln per category
    # for k, v in tool_results['q_findings_per_category'].items():
    #     vulns_per_category[k] = vulns_per_category.get(k, 0) + v

# get percentage of contracts that have at least one vulnerability
q_contracts = len(cat_per_contract)
q_contract_per_cat = {}
total_contracts_with_vuln = 0
for contract, cats in cat_per_contract.items():
    if (any([c != 'Ignore' for c in cats])):
        total_contracts_with_vuln += 1

    for cat in cats:
        q_contract_per_cat[cat] = q_contract_per_cat.get(cat, 0) + 1

percentage_contracts_with_vuln = total_contracts_with_vuln / q_contracts * 100

# for json output
cat_per_contract = {k: list(v) for k, v in cat_per_contract.items()}

timeout_percentage = round(total_timeouts / total_analysis * 100, 2)
success_percentage = round(total_sucessful / total_analysis * 100, 2)
total_avg_duration = round(total_duration / total_analysis, 2)

# clean results
for toolid in results_by_tool:
    tool_results = results_by_tool[toolid]
    tool_results['total_duration'] = round(tool_results['total_duration'], 2)
    tool_results['avg_duration'] = round(tool_results['avg_duration'], 2)
    tool_results['timeout_percentage'] = round(tool_results['timeout_percentage'], 2)
    tool_results['success_percentage'] = round(tool_results['success_percentage'], 2)
    tool_results['contracts_with_vuln_percentage'] = round(tool_results['contracts_with_vuln_percentage'], 2)

    tool_results['errors'] = {}
    tool_results['fails'] = {}
    tool_results['findings_per_contract'] = {}
    tool_results['cat_per_contract'] = {}
    # tool_results['findings_per_contract'] = {k: list(v) for k, v in tool_results['findings_per_contract'].items()}
    # tool_results['cat_per_contract'] = {k: list(v) for k, v in tool_results['cat_per_contract'].items()}

logger(f'=== Results ===')
results = {
    'results_by_tool': results_by_tool,
    'total_duration': total_duration,
    'total_findings': total_findings,
    'total_errors': total_errors,
    'total_fails': total_fails,
    'total_sucessful': total_sucessful,
    'total_analysis': total_analysis,
    'total_timeouts': total_timeouts,
    'total_contracts': q_contracts,
    'total_contracts_with_vuln': total_contracts_with_vuln,
    'percentage_contracts_with_vuln': percentage_contracts_with_vuln,
    'timeout_percentage': timeout_percentage,
    'success_percentage': success_percentage,
    # 'vulns_per_category': vulns_per_category,
    'total_avg_duration': total_avg_duration,
    'q_contract_per_cat': q_contract_per_cat,
    'unmapped_list': list(unmapped_list),
    # 'contract_per_cat': contract_per_cat, # too big
}

# print(results)

with open(OUTPUT_JSON_FILE, 'w') as fp:
    json.dump(results, fp, indent=4)
# print(json.dumps(results, indent=4))

# ---

# plot vulnerabilities per contract
# import matplotlib.pyplot as plt
# import numpy as np
# OUTPUT_PLOT_FILE=OUTPUT_JSON_FILE.replace('.json', '.png')
# # plt.figure(figsize=(20, 10))
# h = plt.hist(vulns_per_contract.values(), bins=max(vulns_per_contract.values()))
# plt.title('Vulnerabilidades por contrato')
# plt.xlabel('Número de vulnerabilidades')
# plt.ylabel('Número de contratos')
# plt.savefig(OUTPUT_PLOT_FILE)
