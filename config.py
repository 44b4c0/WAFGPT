import os

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
PCAP_IN_DIR = ROOT_DIR + '/datain/pcap/'
TXT_IN_DIR = ROOT_DIR + '/datain/txt/'
CSV_IN_DIR = ROOT_DIR + '/datain/csv/'
PARQUET_IN_PATH = ROOT_DIR + '/datain/parquet/data.parquet'

GOOD_PCAP_OUT_PATH = ROOT_DIR + '/dataout/pcap/good.pcap'
BAD_PCAP_OUT_PATH = ROOT_DIR + '/dataout/pcap/bad.pcap'
SUSP_PCAP_OUT_PATH = ROOT_DIR + '/dataout/pcap/sus.pcap'

GOOD_PARQUET_OUT_PATH = ROOT_DIR + '/dataout/parquet/good.parquet'
BAD_PARQUET_OUT_PATH = ROOT_DIR + '/dataout/parquet/bad.parquet'
SUSP_PARQUET_OUT_PATH = ROOT_DIR + '/dataout/parquet/sus.parquet'

PCAP_GUESS_IN_DIR = ROOT_DIR + '/datain/pcap_guess/'

MODEL_OUT_PATH = ROOT_DIR + '/ai/wafgpt.pth'
VECTORIZER_OUT_PATH = ROOT_DIR + '/ai/vectorizer.pkl'

LLAMA_CPP_MODEL_PATH = ROOT_DIR + '/ai/llamacpp.gguf'

LLAMA_CPP_CLI_PATH = 'C:\\Windows\\System32\\llama-cli.exe'

API_PCAP_FILE_UPLOAD_DIR = ROOT_DIR + '/datain/api/pcap/'
API_PARQUET_FILE_PATH = ROOT_DIR + '/datain/api/parquet/'

EPOCH_NUMS = 10