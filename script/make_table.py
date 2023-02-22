import json
import datetime

with open('../metadata/first-run.json') as fp:
    data = json.load(fp)

print('\\hline')
print('# & Ferramentas & Tempo médio & Total \\\\')
print('\\hline')

i = 0
for toolid in data['results_by_tool']:
    tooldata = data['results_by_tool'][toolid]
    total_duration = datetime.timedelta(seconds=int(tooldata['total_duration']))
    avg_duration = datetime.timedelta(seconds=int(tooldata['avg_duration']))
    print(i, end=' & ')
    print(toolid, end=' & ')
    print(avg_duration, end=' & ')
    print(total_duration, end=' ')
    print('\\\\')
    i += 1

print('\\hline')
total_avg_duration = str(datetime.timedelta(seconds=int(data['total_avg_duration'])))
total_duration = str(datetime.timedelta(seconds=int(data['total_duration'])))
print('\multicolumn{2}{l}{Total}', end=' & ')
print(f'{total_avg_duration} & {total_duration} \\\\')
print('\\hline')

print('')
print('')

# print('Ferramenta & Tempo de execução total & Tempo médio \\\\')
# print('\\hline')
# i = 0
# for toolid in data['results_by_tool']:
#     tooldata = data['results_by_tool'][toolid]
#     vulns = tooldata['vulns_per_category']
# i += 1

#     print('\\\\')

# print('\\hline')