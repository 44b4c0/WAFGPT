from flask import Flask

from config import API_PCAP_FILE_UPLOAD_DIR

def StartAPI():
    app = Flask(__name__)
    app.config["PCAP_DIR"] = API_PCAP_FILE_UPLOAD_DIR

    return app