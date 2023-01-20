import sys
import csv
import json

# get the first arg as the input csv
INPUT_CSV_FILE = sys.argv[1]
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

# results
n_analysis_by_tool = {}
total_duration_by_tool = {}
findings_counter_by_tool = {}
errors_counter_by_tool = {}

# ----------------

def logger(msg):
    if SHOULD_PRINT:
        print(msg)

def process_row(line):
    global n_analysis_by_tool, total_duration_by_tool, findings_counter_by_tool, errors_counter_by_tool

    v = {}
    for header, value in zip(CSV_HEADERS, line):
        v[header] = value
        # print(f"{header}: {value}")

    logger(f"processing {v['basename']}...")

    total_duration_by_tool[v['toolid']] = total_duration_by_tool.get(v['toolid'], 0) + float(v['duration'])
    n_analysis_by_tool[v['toolid']] = n_analysis_by_tool.get(v['toolid'], 0) + 1

    for finding in v['findings'].split(','):
        finding = finding.strip()
        if finding == '':
            continue
        if v['toolid'] not in findings_counter_by_tool:
            findings_counter_by_tool[v['toolid']] = {}
        if finding not in findings_counter_by_tool[v['toolid']]:
            findings_counter_by_tool[v['toolid']][finding] = 0
        findings_counter_by_tool[v['toolid']][finding] += 1

    for error in v['errors'].split(','):
        error = error.strip()
        if error == '':
            continue
        if v['toolid'] not in errors_counter_by_tool:
            errors_counter_by_tool[v['toolid']] = {}
        if error not in errors_counter_by_tool[v['toolid']]:
            errors_counter_by_tool[v['toolid']][error] = 0
        errors_counter_by_tool[v['toolid']][error] += 1

    for error in v['fails'].split(','):
        error = error.strip()
        if error == '':
            continue
        if v['toolid'] not in errors_counter_by_tool:
            errors_counter_by_tool[v['toolid']] = {}
        if error not in errors_counter_by_tool[v['toolid']]:
            errors_counter_by_tool[v['toolid']][error] = 0
        errors_counter_by_tool[v['toolid']][error] += 1

# read the csv file line by line
with open(INPUT_CSV_FILE, 'r') as fp:
    csvreader = csv.reader(fp)

    # skip the header
    csvreader.__next__()

    # process lines
    for row in csvreader:
        process_row(row)

# average_duration_per_tool
average_duration_per_tool = {}

for tool in n_analysis_by_tool:
    average_duration_per_tool[tool] = total_duration_by_tool[tool] / n_analysis_by_tool[tool]

total_duration = sum(total_duration_by_tool.values())

total_vuln_by_tool = {}

for tool in findings_counter_by_tool:
    total_vuln_by_tool[tool] = sum(findings_counter_by_tool[tool].values())

total_vuln = sum(total_vuln_by_tool.values())

total_errors_by_tool = {}

for tool in errors_counter_by_tool:
    total_errors_by_tool[tool] = sum(errors_counter_by_tool[tool].values())

total_errors = sum(total_errors_by_tool.values())

n_sucessful_analysis_by_tool = {}

for tool in n_analysis_by_tool:
    n_sucessful_analysis_by_tool[tool] = n_analysis_by_tool[tool] - total_errors_by_tool.get(tool, 0)

n_analysis = sum(n_sucessful_analysis_by_tool.values())

logger(f'=== Results ===')
results = {
    'n_analysis_by_tool': n_analysis_by_tool,
    'total_duration_by_tool': total_duration_by_tool,
    'findings_counter_by_tool': findings_counter_by_tool,
    'errors_counter_by_tool': errors_counter_by_tool,
    'total_duration': total_duration,
    'average_duration_per_tool': average_duration_per_tool,
    'total_vuln_by_tool': total_vuln_by_tool,
    'total_vuln': total_vuln,
    'total_errors_by_tool': total_errors_by_tool,
    'total_errors': total_errors,
    'n_sucessful_analysis_by_tool': n_sucessful_analysis_by_tool,
    'n_analysis': n_analysis,
}

print(json.dumps(results, indent=4))