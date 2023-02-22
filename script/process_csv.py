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
IGNORED_TOOLS = (sys.argv[3] if len(sys.argv) > 3 else '').split(',')
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

print('dasp_mapping', dasp_mapping)
print('vulnerability_mapping', vulnerability_mapping)

# ----------------

findings_list = []
unmapped_list = set()

def logger(msg):
    if SHOULD_PRINT:
        print(msg)

def process_row(line):
    global results_by_tool

    v = {}
    for header, value in zip(CSV_HEADERS, line):
        v[header] = value

    logger(f"processing {v['basename']}...")

    toolid = v['toolid']

    if (toolid in IGNORED_TOOLS):
        return

    if (not results_by_tool.get(toolid, None)):
        results_by_tool[toolid] = {}
        results_by_tool[toolid]['total_duration'] = 0
        results_by_tool[toolid]['n_analysis'] = 0
        results_by_tool[toolid]['n_findings'] = 0
        results_by_tool[toolid]['n_sucessful'] = 0
        results_by_tool[toolid]['findings'] = {}
        results_by_tool[toolid]['vuln_per_category'] = {}
        results_by_tool[toolid]['cat_per_contract'] = {}
        results_by_tool[toolid]['n_errors'] = 0
        results_by_tool[toolid]['errors'] = {}
        results_by_tool[toolid]['n_fails'] = 0
        results_by_tool[toolid]['fails'] = {}
        results_by_tool[toolid]['infos'] = {}
        results_by_tool[toolid]['vuln_per_contract'] = {}

    results_by_tool[toolid]['total_duration'] += float(v['duration'])
    results_by_tool[toolid]['n_analysis'] += 1

    row_findings = 0
    for finding in v['findings'].split(','):
        finding = finding.strip()
        if (finding == ''):
            continue

        vm = vulnerability_mapping.get(finding, 'Unmapped')
        if (vm == 'Unmapped'):
            unmapped_list.add(finding)
        category = dasp_mapping[vm]

        if (v['basename'] in results_by_tool[toolid]['cat_per_contract']):
            results_by_tool[toolid]['cat_per_contract'][v['basename']].add(category)
        else:
            results_by_tool[toolid]['cat_per_contract'][v['basename']] = set()

        # vuln per category
        results_by_tool[toolid]['vuln_per_category'][category] = results_by_tool[toolid]['vuln_per_category'].get(category, 0) + 1

        fitem = f'{toolid},{finding}'
        if (fitem not in findings_list):
            findings_list.append(fitem)

        if (category == 'Ignore'):
            continue

        results_by_tool[toolid]['n_findings'] += 1
        results_by_tool[toolid]['findings'][finding] = results_by_tool[toolid]['findings'].get(finding, 0) + 1
        row_findings += 1

    results_by_tool[toolid]['vuln_per_contract'][v['basename']] = row_findings

    for info in v['infos'].split(','):
        info = info.strip()
        if info == '':
            continue
        results_by_tool[toolid]['infos'][info] = results_by_tool[toolid]['infos'].get(info, 0) + 1

    for error in v['errors'].split(','):
        error = error.strip()
        if error == '':
            continue
        results_by_tool[toolid]['errors'][error] = results_by_tool[toolid]['errors'].get(error, 0) + 1
        results_by_tool[toolid]['n_errors'] += 1

    row_fails = 0
    for fail in v['fails'].split(','):
        fail = fail.strip()
        if fail == '':
            continue
        results_by_tool[toolid]['fails'][fail] = results_by_tool[toolid]['fails'].get(fail, 0) + 1
        results_by_tool[toolid]['n_fails'] += 1
        row_fails += 1

    results_by_tool[toolid]['n_sucessful'] += 1 if row_fails == 0 else 0

# read the csv file line by line
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
total_timeouts = 0
vulns_per_contract = {}
vulns_per_category = {}
cat_per_contract = {}

for toolid in results_by_tool:
    # average_duration_per_tool
    results_by_tool[toolid]['avg_duration'] = results_by_tool[toolid]['total_duration'] / results_by_tool[toolid]['n_analysis']

    # totals
    total_duration += results_by_tool[toolid]['total_duration']
    total_findings += results_by_tool[toolid]['n_findings']
    total_errors += results_by_tool[toolid]['n_errors']
    total_fails += results_by_tool[toolid]['n_fails']
    total_sucessful += results_by_tool[toolid]['n_sucessful']
    total_analysis += results_by_tool[toolid]['n_analysis']

    # other data
    timeouts = results_by_tool[toolid]['fails'].get('DOCKER_TIMEOUT', 0)
    results_by_tool[toolid]['timeout_percentage'] = timeouts / results_by_tool[toolid]['n_analysis'] * 100
    total_timeouts += timeouts
    results_by_tool[toolid]['success_percentage'] = results_by_tool[toolid]['n_sucessful'] / results_by_tool[toolid]['n_analysis'] * 100
    contracts_with_vuln = 0
    for k, v in results_by_tool[toolid]['vuln_per_contract'].items():
        vulns_per_contract[k] = vulns_per_contract.get(k, 0) + v
        if (v > 0):
            contracts_with_vuln += 1
    results_by_tool[toolid]['contracts_with_vuln'] = contracts_with_vuln
    results_by_tool[toolid]['contracts_with_vuln_percentage'] = contracts_with_vuln / len(results_by_tool[toolid]['vuln_per_contract']) * 100

    for contract in results_by_tool[toolid]['cat_per_contract']:
        # results_by_tool[toolid]['cat_per_contract'][k] = list(results_by_tool[toolid]['cat_per_contract'][k])
        cat_per_contract[contract] = (cat_per_contract[contract] if contract in cat_per_contract else set()).union(results_by_tool[toolid]['cat_per_contract'][contract])

    results_by_tool[toolid]['contract_per_cat'] = {}
    for contract in results_by_tool[toolid]['cat_per_contract']:
        for cat in results_by_tool[toolid]['cat_per_contract'][contract]:
            results_by_tool[toolid]['contract_per_cat'][cat] = results_by_tool[toolid]['contract_per_cat'].get(cat, 0) + 1

    # vuln per category
    for k, v in results_by_tool[toolid]['vuln_per_category'].items():
        vulns_per_category[k] = vulns_per_category.get(k, 0) + v

    # tratar quando deu erro não considerar no % de sucesso/vulnerabilidades

# get percentage of contracts that have at least one vulnerability
total_contracts_with_vuln = len([k for k, v in vulns_per_contract.items() if v > 0])
percentage_contracts_with_vuln = total_contracts_with_vuln / len(vulns_per_contract) * 100
cat_per_contract = {k: list(v) for k, v in cat_per_contract.items()}

contract_per_cat = {}
for contract in cat_per_contract:
    for cat in cat_per_contract[contract]:
        contract_per_cat[cat] = contract_per_cat.get(cat, 0) + 1

timeout_percentage = total_timeouts / total_analysis * 100
success_percentage = total_sucessful / total_analysis * 100
total_avg_duration = total_duration / total_analysis

# clean results
for toolid in results_by_tool:
    results_by_tool[toolid]['total_duration'] = round(results_by_tool[toolid]['total_duration'], 2)
    results_by_tool[toolid]['avg_duration'] = round(results_by_tool[toolid]['avg_duration'], 2)
    results_by_tool[toolid]['timeout_percentage'] = round(results_by_tool[toolid]['timeout_percentage'], 2)
    results_by_tool[toolid]['success_percentage'] = round(results_by_tool[toolid]['success_percentage'], 2)
    results_by_tool[toolid]['contracts_with_vuln_percentage'] = round(results_by_tool[toolid]['contracts_with_vuln_percentage'], 2)

    results_by_tool[toolid]['errors'] = {}
    results_by_tool[toolid]['fails'] = {}
    results_by_tool[toolid]['vuln_per_contract'] = {}
    results_by_tool[toolid]['cat_per_contract'] = {}

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
    'total_contracts': len(vulns_per_contract),
    'total_contracts_with_vuln': total_contracts_with_vuln,
    'percentage_contracts_with_vuln': percentage_contracts_with_vuln,
    'timeout_percentage': timeout_percentage,
    'success_percentage': success_percentage,
    'vulns_per_category': vulns_per_category,
    'findings_list': findings_list,
    'total_avg_duration': total_avg_duration,
    'unmapped_list': list(unmapped_list),
    # 'cat_per_contract': cat_per_contract,
    'contract_per_cat': contract_per_cat,
}

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
