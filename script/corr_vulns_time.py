import json
import matplotlib

with open('../metadata/first-run-no-solhint.json') as fp:
# with open('../metadata/first-run.json') as fp:
    data = json.load(fp)

xy = []
for tool, tooldata in data['results_by_tool'].items():
    # duration = int(tooldata['avg_duration'])
    duration = int(tooldata['total_duration'])
    vulns = tooldata['contracts_with_vuln']
    xy.append((duration, vulns))
    print('{:20s}: {:>10}, {:>10}'.format(tool, duration, vulns))


# plot the data
matplotlib.use('Agg')
import matplotlib.pyplot as plt
plt.scatter(*zip(*xy))
plt.xlabel('Tempo de execução total (s)')
plt.ylabel('Número de contratos com vulnerabilidades')
plt.savefig('../metadata/corr_vulns_time.png')
