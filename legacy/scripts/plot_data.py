import os
import json
import sys
import csv
import datetime

# import matplotlib.pyplot as plt
# from matplotlib.dates import (YEARLY, DateFormatter,
#                               rrulewrapper, RRuleLocator, drange)
# plt.rcParams.update({'text.usetex': True})
# plt.style.use('kpmg')

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))

# get the first arg as the input json
INPUT_JSON_FILE = sys.argv[1]

# read json file
with open(INPUT_JSON_FILE, 'r') as fp:
    results_json = json.load(fp)

print(json.dumps(results_json, indent=4))
