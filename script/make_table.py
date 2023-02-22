import json
import datetime

with open('../metadata/first-run.json') as fp:
    data = json.load(fp)

print('\\hline')

i = 0
for toolid in data['results_by_tool']:
    tooldata = data['results_by_tool'][toolid]
    total_duration = datetime.timedelta(seconds=int(tooldata['total_duration']))
    avg_duration = datetime.timedelta(seconds=int(tooldata['avg_duration']))
    print(i, end=' & ')
    print('{:15s}'.format(toolid), end=' & ')
    print(str(avg_duration).replace('days', 'dias'), end=' & ')
    print(str(total_duration).replace('days', 'dias'), end=' ')
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
category_list = data['contract_per_cat'].keys()

print('\\hline')
print('\\textbf{Categoria}', end=' & ')
for tool in tool_list:
    print('\\textbf{', tool, '}', end=' & ')
print('\\textbf{Total} \\\\')
print('\\hline')

for category in category_list:
    print(category, end=' & ')
    for tool in tool_list:
        v = data['results_by_tool'][tool]['contract_per_cat'][category] if category in data['results_by_tool'][tool]['contract_per_cat'] else 0
        print(v, end=' & ')
    print(0,'\\\\')
    # print(data['results_by_tool'][tool]['total_contracts'],'\\\\')

print('\\hline')
print('\\textbf{Total}', end=' & ')
for tool in tool_list:
    v = data['results_by_tool'][tool]['contracts_with_vuln']
    print(v, end=' & ')
print(data['total_contracts_with_vuln'],'\\\\')
print('\\hline')



