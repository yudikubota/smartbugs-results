import sys
import csv
import json
import traceback

# get the first arg as the input csv
INPUT_CSV_FILE = sys.argv[1]
OUTPUT_JSON_FILE = sys.argv[2]
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

    if (not results_by_tool.get(toolid, None)):
        results_by_tool[toolid] = {}
        results_by_tool[toolid]['total_duration'] = 0
        results_by_tool[toolid]['n_analysis'] = 0
        results_by_tool[toolid]['n_findings'] = 0
        results_by_tool[toolid]['findings'] = {}
        results_by_tool[toolid]['n_errors'] = 0
        results_by_tool[toolid]['errors'] = {}
        results_by_tool[toolid]['n_fails'] = 0
        results_by_tool[toolid]['fails'] = {}
        results_by_tool[toolid]['infos'] = {}

    results_by_tool[toolid]['total_duration'] += float(v['duration'])
    results_by_tool[toolid]['n_analysis'] += 1

    for finding in v['findings'].split(','):
        finding = finding.strip()
        if finding == '':
            continue
        results_by_tool[toolid]['n_findings'] += 1
        results_by_tool[toolid]['findings'][finding] = results_by_tool[toolid]['findings'].get(finding, 0) + 1

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

    for fail in v['fails'].split(','):
        fail = fail.strip()
        if fail == '':
            continue
        results_by_tool[toolid]['fails'][fail] = results_by_tool[toolid]['fails'].get(fail, 0) + 1
        results_by_tool[toolid]['n_fails'] += 1

    # TODO: avaliate if analysis was successful

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
            print(f"")
            print(f"Row counter: {row_counter}")
            process_row(row)
        except Exception as e:
            print(f"Error: {e}")
            traceback.print_tb(e.__traceback__)
            print(f"Row: {row}")

total_duration = 0
total_findings = 0
total_errors = 0
total_fails = 0
total_sucessful = 0

for toolid in results_by_tool:
    # average_duration_per_tool
    results_by_tool[toolid]['avg_duration'] = results_by_tool[toolid]['total_duration'] / results_by_tool[toolid]['n_findings']

    # sucessful
    results_by_tool[toolid]['n_sucessful'] = results_by_tool[toolid]['n_analysis'] - results_by_tool[toolid]['n_fails']

    # totals
    total_duration += results_by_tool[toolid]['total_duration']
    total_findings += results_by_tool[toolid]['n_findings']
    total_errors += results_by_tool[toolid]['n_errors']
    total_fails += results_by_tool[toolid]['n_fails']
    total_sucessful += results_by_tool[toolid]['n_sucessful']


logger(f'=== Results ===')
results = {
    'results_by_tool': results_by_tool,
    'total_duration': total_duration,
    'total_findings': total_findings,
    'total_errors': total_errors,
    'total_fails': total_fails,
    'total_sucessful': total_sucessful,
}

with open(OUTPUT_JSON_FILE, 'w') as fp:
    json.dump(results, fp, indent=4)
# print(json.dumps(results, indent=4))