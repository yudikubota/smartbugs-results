python3 process_csv.py ../first-run.csv ../metadata/first-run.json &
python3 process_csv.py ../first-run.csv ../metadata/first-run-no-solhint.json solhint &
wait