import json

with open('../metadata/first-run.json') as fp:
    data = json.load(fp)

print('Ferramenta & Tempo de execução total & Tempo médio \\\\')
print('\\hline')

for toolid in data['results_by_tool']:
    tooldata = data['results_by_tool'][toolid]
    total_duration = f"{round(tooldata['total_duration'] / 60 / 60, 0)} h"
    avg_duration = f"{round(tooldata['avg_duration'] / 60, 0)} min"
    print(toolid, end=' & ')
    print(total_duration, end=' & ')
    print(avg_duration, end=' ')
    print('\\\\')

print('\\hline')