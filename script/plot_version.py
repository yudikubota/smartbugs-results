import matplotlib.pyplot as plt
import numpy as np
from collections import OrderedDict
import semver
from functools import cmp_to_key


# execução no total
# dist = {'0.8.7': 1025, '0.8.0': 6402, '0.8.11': 369, '0.4.19': 315, '0.6.12': 1040, '0.8.15': 324, '0.4.17': 61, '0.6.8': 46, '0.5.16': 125, '0.5.0': 509, '0.4.16': 158, '0.8.13': 536, '0.8.4': 4071, '0.4.24': 1274, '0.4.11': 224, '0.8.10': 572, '0.8.17': 470, '0.8.12': 466, '0.8.9': 2183, '0.6.0': 627, '0.5.1': 49, '0.4.13': 148, '0.4.25': 713, '0.5.6': 25, '0.8.6': 295, '0.5.5': 20, '0.4.18': 800, '0.7.4': 90, '0.8.1': 365, '0.8.5': 170, '0.5.14': 25, '0.6.2': 98, '0.8.14': 132, '0.7.0': 290, '0.5.12': 41, '0.8.2': 170, '0.5.11': 94, '0.4.23': 274, '0.4.4': 85, '0.4.26': 82, '0.7.5': 28, '0.8.16': 190, '0.4.20': 438, '0.5.8': 70, '0.4.0': 98, '0.4.21': 262, '0.4.15': 131, '0.8.8': 70, '0.4.12': 21, '': 137, '0.6.3': 12, '0.4.22': 137, '0.4.8': 66, '0.5.10': 86, '0.7.6': 170, '0.6.10': 24, '0.8.3': 89, '0.6.11': 66, '0.4': 13, '0.5.17': 146, '0.5.7': 57, '0.5.2': 55, '0.5.13': 19, '0.6.7': 9, '0.4.10': 41, '0.8': 17, '0.7.3': 28, '0.6.4': 17, '0.6.6': 96, '0.4.2': 59, '0.5.15': 15, '0.6.9': 11, '0.5.4': 33, '0.4.9': 42, '0.5.3': 18, '0.4.7': 20, '0.1.1': 3, '0.7.1': 24, '0.5.9': 29, '0.4.14': 12, '0.6': 8, '0.6.1': 10, '0.8.08.12.0': 1, '0.5': 7, '0.4.99': 5, '0.4.6': 25, '0.8.11.0': 2, '0.6.5': 2, '0.7.2': 6, '0.4.3': 3, '0.4.1': 8, '0.8.00': 1}
# no_version_counter 459
# invalid_version_counter 1736
# all_versions_counter 27700
# total 29895

# execução apenas com os copiados
dist1 = {'0.8.7': 724, '0.8.0': 4364, '0.4.19': 314, '0.6.12': 944, '0.4.17': 61, '0.5.0': 485, '0.4.16': 158, '0.8.13': 302, '0.8.4': 3157, '0.8.11': 228, '0.4.24': 1269, '0.4.11': 224, '0.8.10': 395, '0.8.17': 257, '0.8.12': 359, '0.8.9': 972, '0.5.1': 49, '0.6.0': 529, '0.4.13': 148, '0.4.25': 710, '0.5.6': 24, '0.5.5': 20, '0.4.18': 800, '0.7.4': 79, '0.8.1': 332, '0.8.5': 155, '0.5.14': 24, '0.6.2': 83, '0.7.0': 129, '0.5.16': 97, '0.5.12': 41, '0.8.2': 19, '0.8.15': 212, '0.5.11': 93, '0.4.23': 274, '0.4.4': 85, '0.4.26': 81, '0.7.5': 22, '0.8.16': 113, '0.4.20': 438, '0.5.8': 70, '0.4.0': 98, '0.8.6': 147, '0.6.8': 40, '0.4.21': 260, '0.4.15': 130, '0.4.12': 21, '': 120, '0.6.3': 12, '0.4.22': 116, '0.4.8': 65, '0.5.10': 85, '0.7.6': 85, '0.8.3': 57, '0.6.11': 54, '0.4': 13, '0.5.17': 128, '0.8.8': 45, '0.5.7': 54, '0.5.2': 55, '0.5.13': 19, '0.6.7': 7, '0.4.10': 41, '0.8': 11, '0.8.14': 69, '0.6.4': 14, '0.6.6': 81, '0.7.3': 12, '0.4.2': 59, '0.5.15': 15, '0.6.9': 10, '0.5.4': 33, '0.4.9': 42, '0.5.3': 18, '0.4.7': 20, '0.1.1': 3, '0.5.9': 25, '0.4.14': 12, '0.6': 7, '0.6.1': 7, '0.6.10': 10, '0.5': 7, '0.4.99': 5, '0.4.6': 25, '0.7.1': 15, '0.7.2': 5, '0.4.3': 3, '0.4.1': 8, '0.6.5': 1}
# no_version_counter 459
# invalid_version_counter 730
# all_versions_counter 21009
print('dist1 sum', sum(dist1.values()))

# resultado das versões do ff
dist2 = {"0.8.18": 5279, "0.6.8": 3, "0.7.4": 5, "0.8.6": 59, "0.8.16": 21, "0.8.10": 48, "0.8.12": 35, "0.8.0": 24, "0.7.6": 181, "0.8.13": 60, "0.8.4": 70, "0.8.2": 18, "0.8.15": 39, "0.8.11": 61, "0.8.17": 104, "0.6.12": 59, "0.7.3": 6, "0.8.9": 103, "0.8.14": 29, "0.4.24": 2, "0.7.5": 4, "0.8.7": 63, "0.8.5": 8, "0.5.17": 16, "0.7.1": 3, "0.8.3": 7, "0.6.6": 5, "0.8.8": 6, "0.6.10": 3, "0.5.16": 3, "0.5.9": 3, "0.6.4": 4, "0.6.11": 8, "0.8.1": 3, "0.6.1": 1, "0.7.0": 3, "0.6.2": 1, "0.5.14": 1, "0.5.11": 2, "0.7.2": 1}
# total 6351
print('dist2 sum', sum(dist2.values()))

# handle invalid semver versions
for key in dist1:
    split = key.split('.')
    if len(split) == 2:
        print('invalid version', key)
        new_key = '.'.join(split[:3]) + '.0'
        print('transforming into', new_key)
        dist1[new_key] = dist1.get(new_key, 0) + dist1[key]
        print('total:', dist1[new_key])
        dist1[key] = None
    if len(split) == 1:
        print('invalid version. removing', key)
        dist1[key] = None

dist1 = {k: v for k, v in dist1.items() if v is not None}

# merge the 2 dicts
dist = {}
for key in dist1:
    if key in dist2:
        dist[key] = dist1[key] + dist2[key]
    else:
        dist[key] = dist1[key]
for key in dist2:
    if key not in dist1:
        dist[key] = dist2[key]

# {'0.1.1': 3, '0.4.0': 13, '0.4.1': 8, '0.4.2': 59, '0.4.3': 3, '0.4.4': 85, '0.4.6': 25, '0.4.7': 20, '0.4.8': 65, '0.4.9': 42, '0.4.10': 41, '0.4.11': 224, '0.4.12': 21, '0.4.13': 148, '0.4.14': 12, '0.4.15': 130, '0.4.16': 160, '0.4.17': 63, '0.4.18': 800, '0.4.19': 316, '0.4.20': 438, '0.4.21': 260, '0.4.22': 116, '0.4.23': 274, '0.4.24': 1271, '0.4.25': 710, '0.4.26': 81, '0.4.99': 5, '0.5.0': 7, '0.5.1': 49, '0.5.2': 55, '0.5.3': 18, '0.5.4': 33, '0.5.5': 20, '0.5.6': 24, '0.5.7': 54, '0.5.8': 70, '0.5.9': 28, '0.5.10': 85, '0.5.11': 95, '0.5.12': 41, '0.5.13': 19, '0.5.14': 25, '0.5.15': 15, '0.5.16': 100, '0.5.17': 144, '0.6.0': 7, '0.6.1': 8, '0.6.2': 84, '0.6.3': 12, '0.6.4': 18, '0.6.5': 1, '0.6.6': 86, '0.6.7': 7, '0.6.8': 43, '0.6.9': 10, '0.6.10': 13, '0.6.11': 62, '0.6.12': 1005, '0.7.0': 132, '0.7.1': 18, '0.7.2': 6, '0.7.3': 18, '0.7.4': 84, '0.7.5': 26, '0.7.6': 266, '0.8.0': 35, '0.8.1': 335, '0.8.2': 37, '0.8.3': 64, '0.8.4': 3229, '0.8.5': 163, '0.8.6': 206, '0.8.7': 793, '0.8.8': 51, '0.8.9': 1075, '0.8.10': 443, '0.8.11': 289, '0.8.12': 394, '0.8.13': 364, '0.8.14': 98, '0.8.15': 251, '0.8.16': 134, '0.8.17': 361}

# order by version according to semver
dist = OrderedDict(sorted(dist.items(), key=lambda t: semver.VersionInfo.parse(t[0])))

# dist = sorted(dist.items(), key=cmp_to_key(lambda a, b: semver.compare(a, b) ))
# dist = OrderedDict(sorted(dist.items(), key=cmp_to_key(lambda a, b: semver.compare(a, b) )))
# dist = OrderedDict(sorted(dist.items(), key=lambda t: t[0]))

# sum of all versions
expected_total = sum(dist1.values()) + sum(dist2.values())
total = sum(dist.values())

print(dist)
print(dict(dist.items()))
print('expected_total', expected_total)
print('total', total)

# fig, (ax1, ax2) = plt.subplots(1, 2, sharey=True)

# fig.suptitle('Distribuição das versões de solidity')

# plot version distribution
# ax1.title('Distribuição das versões de solidity em ordem cronológica')
# ax1.bar(range(len(dist)), dist.values(), align='center')
# ax1.xticks(range(len(dist)), dist.keys(), rotation=90)

# order by value
# dist = OrderedDict(sorted(dist.items(), key=lambda t: t[1], reverse=True))
# print('5 most common', list(dist.items())[:5])

# plot version distribution
# ax2.title('Distribuição das versões de solidity em ordem de ocorrência')
# ax2.bar(range(len(dist)), dist.values(), align='center')
# ax2.xticks(range(len(dist)), dist.keys(), rotation=90)

# fig.savefig('../metadata/plot_version.png')

# plot version distribution ordered by version number with axis labels
plt.title('Distribuição das versões de solidity')
plt.bar(range(len(dist)), dist.values(), align='center')
# print x axis labels in order jumping a number of labels to avoid overlapping but always show the last label.
# Also, smaller font and no rotation.
xtick_positions = range(0, len(dist), int(len(dist)/10))
print('xtick_positions', xtick_positions)
xtick_labels = [list(dist.keys())[i] for i in xtick_positions]
plt.xticks(xtick_positions, xtick_labels, rotation=0, fontsize=8)
plt.xlabel('Versão')
plt.ylabel('Número de contratos')
plt.savefig('../metadata/plot_version.png')

