import json
import datetime

with open('../metadata/first-run-no-solhint.json') as fp:
# with open('../metadata/first-run.json') as fp:
    data = json.load(fp)

print('\\hline')

i = 0
for toolid in data['results_by_tool']:
    tooldata = data['results_by_tool'][toolid]
    total_duration = datetime.timedelta(seconds=int(tooldata['total_duration']))
    avg_duration = datetime.timedelta(seconds=int(tooldata['avg_duration']))
    timeout = 'sim' if tooldata['n_timeouts'] > 0 else 'não'
    print(i, end=' & ')
    print('{:15s}'.format(toolid), end=' & ')
    print(str(avg_duration).replace('days', 'dias'), end=' & ')
    print(str(total_duration).replace('days', 'dias'), end=' & ')
    print(timeout, end=' ')
    print('\\\\')
    i += 1

print('\\hline')
total_avg_duration = str(datetime.timedelta(seconds=int(data['total_avg_duration']))).replace('days', 'dias')
total_duration = str(datetime.timedelta(seconds=int(data['total_duration']))).replace('days', 'dias')
print('\multicolumn{2}{l}{Total}', end=' & ')
print(f'{total_avg_duration} & {total_duration} \\\\')
print('\\hline')
print('')
print('------------------------------')
print('')

# make a latex table with tools and categories

tool_list = data['results_by_tool'].keys()
category_list = [
    'Reentrancy',
    'Access Control',
    'Arithmetic',
    'Unchecked Low Level Calls',
    'Denial of Services',
    'Bad Randomness',
    'Front Running',
    'Time Manipulation',
    'Short Addresses',
    'Unknown Unknowns'
]
total_contracts = data['total_contracts']
included_tools = []
# included_tools = ['solhint-3.3.8']

print('\\hline')
print('\\textbf{Categoria}', end=' & ')
for i, tool in enumerate(tool_list):
    if (len(included_tools) and tool not in included_tools):
        continue
    # print('\\textbf{', i, '}', end=' & ')
    print('\\textbf{', tool, '}', end=' & ')
print('\\textbf{Total} \\\\')
print('\\hline')

for i, category in enumerate(category_list):
    print(f'DASP-{i+1}', end=' & ')
    # print(i, end=' & ')
    # print(category, end=' & ')
    for tool in tool_list:
        if (len(included_tools) and tool not in included_tools):
            continue
        v = data['results_by_tool'][tool]['q_contract_per_cat'][category] if category in data['results_by_tool'][tool]['q_contract_per_cat'] else 0
        p = int(v / total_contracts * 100)
        v = f'{v} {p}\%'
        print(v, end=' & ')

    v = data['q_contract_per_cat'][category] if category in data['q_contract_per_cat'] else 0
    p = int(v / total_contracts * 100)
    v = f'{v} {p}\%'
    print(v,'\\\\')
    # print(data['results_by_tool'][tool]['total_contracts'],'\\\\')

print('\\hline')
print('\\textbf{Total}', end=' & ')
for tool in tool_list:
    if (len(included_tools) and tool not in included_tools):
        continue
    v = data['results_by_tool'][tool]['contracts_with_vuln']
    p = int(v / total_contracts * 100)
    v = f'{v} {p}\%'
    print(v, end=' & ')
v = data['total_contracts_with_vuln']
p = int(v / total_contracts * 100)
print(f'{v} {p}\%','\\\\')
print('\\hline')



