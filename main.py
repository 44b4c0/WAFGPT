import pandas as pd
import argparse
import os

from flask import request

from config import BAD_PCAP_OUT_PATH, GOOD_PCAP_OUT_PATH, GOOD_PARQUET_OUT_PATH, BAD_PARQUET_OUT_PATH, SUSP_PARQUET_OUT_PATH, SUSP_PCAP_OUT_PATH, PARQUET_IN_PATH, API_PARQUET_FILE_PATH
from modules.aitrainer import LoadParquet, LoadModel, TrainModel
from modules.llamacpp import AnalyzeParquet
from modules.dataparser import PcapSplit, PcapToParquet
from modules.api import StartAPI

parser = argparse.ArgumentParser(description='Args')
parser.add_argument('--action', type=str)

args = parser.parse_args()

if args.method == 'train':
    PcapSplit()

    PcapToParquet(GOOD_PCAP_OUT_PATH, GOOD_PARQUET_OUT_PATH)
    PcapToParquet(BAD_PCAP_OUT_PATH, BAD_PARQUET_OUT_PATH)
    PcapToParquet(SUSP_PCAP_OUT_PATH, SUSP_PCAP_OUT_PATH)

    good_parquet_file = LoadParquet(GOOD_PARQUET_OUT_PATH, 'good')
    bad_parquet_file = LoadParquet(BAD_PARQUET_OUT_PATH, 'bad')
    sus_parquet_file = LoadParquet(SUSP_PARQUET_OUT_PATH, 'sus')

    concatinated = pd.concat([good_parquet_file, bad_parquet_file, sus_parquet_file], ignore_index=True)

    TrainModel(concatinated=concatinated)
elif args.method == 'custom':
    app = StartAPI()

    app.run(host='0.0.0.0', port=8000)

    @app.route('/api/pcap/check', methods=['POST'])
    def PcapCheck():
        if 'file' not in request.files:
            return {'error': 'no files found'}

        file = request.files['file']

        if file.filename == '':
            return {'error': 'invalid file name'}

        file_path = os.path.join(app.config['PCAP_DIR'], file.filename)
        file.save(file_path)

        results = LoadModel()

        return {'success': results}

elif args.method == 'llamacpp':
    app = StartAPI()

    app.run(host='0.0.0.0', port=8000)

    @app.route('/api/pcap/check', methods=['POST'])
    def PcapCheck():
        if 'file' not in request.files:
            return {'error': 'no files found'}

        file = request.files['file']

        if file.filename == '':
            return {'error': 'invalid file name'}

        file_path = os.path.join(app.config['PCAP_DIR'], file.filename)
        if os.path.exists(file_path):
            return {'error': 'invalid file name'}

        file.save(file_path)

        PcapToParquet(file_path, API_PARQUET_FILE_PATH + file.filename + '.parquet')

        data_frame = pd.read_parquet(API_PARQUET_FILE_PATH + file.filename + '.parquet')

        AnalyzeParquet(data_frame)

        return {'success': data_frame}
    
    print('[START]: API Started on 0.0.0.0:8000')
else:
    pass