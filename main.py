import pandas as pd
import sys

from config import BAD_PCAP_OUT_PATH, GOOD_PCAP_OUT_PATH, GOOD_PARQUET_OUT_PATH, BAD_PARQUET_OUT_PATH, SUSP_PARQUET_OUT_PATH, SUSP_PCAP_OUT_PATH
from modules.aitrainer import LoadParquet, LoadModel, TrainModel
from modules.dataparser import PcapSplit, PcapToParquet

PcapSplit()

PcapToParquet(GOOD_PCAP_OUT_PATH, GOOD_PARQUET_OUT_PATH)
PcapToParquet(BAD_PCAP_OUT_PATH, BAD_PARQUET_OUT_PATH)
PcapToParquet(SUSP_PCAP_OUT_PATH, SUSP_PCAP_OUT_PATH)

good_parquet_file = LoadParquet(GOOD_PARQUET_OUT_PATH, 'good')
bad_parquet_file = LoadParquet(BAD_PARQUET_OUT_PATH, 'bad')
sus_parquet_file = LoadParquet(SUSP_PARQUET_OUT_PATH, 'sus')

concatinated = pd.concat([good_parquet_file, bad_parquet_file, sus_parquet_file], ignore_index=True)

TrainModel(concatinated=concatinated)
results = LoadModel()

print('Do you want to startup a Flask API? (Y/n)')
flask_answer = input()

if flask_answer[0] in set(['N', 'n']):
    sys.exit(0)

