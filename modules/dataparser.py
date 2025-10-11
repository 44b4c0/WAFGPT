from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.utils import PcapReader, RawPcapReader
from scapy.all import IP, TCP, wrpcap
import pyarrow.parquet as pq
from pathlib import Path
from tqdm import tqdm
import pandas as pd
import pyarrow as pa
import urllib.parse
import ipaddress
import hashlib
import html
import re
import os

from config import PCAP_IN_DIR, BAD_PCAP_OUT_PATH, TXT_IN_DIR, GOOD_PCAP_OUT_PATH, SUSP_PCAP_OUT_PATH, CSV_IN_DIR

def DetectAttacks(data, url=None):
    FLAGS = re.IGNORECASE

    xss_tags_re = re.compile(r"(?ix)(<\s*script\b)|(<\s*iframe\b)|(<\s*object\b)|(<\s*embed\b)|(<\s*svg[^>]*on\w+\s*=)|(on(?:error|load|mouseover|focus|blur|click|submit)\s*=)|(javascript\s*:)|(document\.cookie)|(window\.location)|(<\s*img[^>]*src\s*=\s*['\"]?\s*data:)", FLAGS)
    xss_script_re = re.compile(r"(?i)<\s*script\b|on\w+\s*=|javascript\s*:", FLAGS)

    sqli_short_re = re.compile(r"(?i)(\bunion\b.*\bselect\b|(--|#|/\*)|(\bor\b|\band\b)\s+1=1|;\s*(drop|insert|update|delete)\b)")

    cmdi_re = re.compile(r"(?ix)(`[^`]*`)|(\$\([^)]*\))|(\|\|)|(\&\&)|(;)|(\|)|(>\s*/dev/null)|(\b(?:wget|curl|nc|ncat|bash|sh|cmd|powershell|python|perl)\b)", FLAGS)
    cmdi_simple_re = re.compile(r"(?i)(`|\$\(.*\)|\s[;|&]{1,2}\s|>\s|&&|\|\|)")

    file_inclusion_re = re.compile(r"(?ix)(\.\./)|(\.\.\\)|(\/etc\/passwd)|(php:\/\/(?:input|filter|memory))|(expect:\/\/)|(file:\/\/)|(\b(?:\w+\.php\?|\binclude\b|\brequire\b))", FLAGS)
    path_traversal_re = re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\\)", FLAGS)

    xxe_re = re.compile(r"(?ix)(<!DOCTYPE[^>]+>|<!ENTITY\s+|SYSTEM\s+|PUBLIC\s+|external\-entity)", FLAGS)

    ldap_re = re.compile(r"(?ix)(\(\s*\|\s*\(|\*\)|\(\s*\!\s*|\(\s*uid\s*=\s*\*\s*\))", FLAGS)

    open_redirect_re = re.compile(r"(?ix)(\b(?:redirect|url|next|return|dest|destination|go)=)([\"']?)(https?:\/\/)", FLAGS)

    multipart_file_re = re.compile(r"(?ix)(Content-Disposition:.*filename=.*\.(php|phtml|phar|jsp|asp|aspx|exe|sh)\b)", FLAGS)

    shell_cmds_re = re.compile(r"(?ix)(/bin/sh|/bin/bash|powershell.exe|Invoke-Expression|nc\s+-e|ncat\s+-e|bash\s+-i\s+>&\s*/dev/tcp)", FLAGS)

    try:
        data = data.decode('utf-8', errors='ignore')
    except:
        data = str(data)
    
    data = urllib.parse.unquote_plus(data)
    data = html.unescape(data)

    if url:
        url = urllib.parse.unquote_plus(url)
        url = html.unescape(url)
    else:
        url = ''
    
    if xss_tags_re.search(data) or xss_tags_re.search(url):
        return 1
    elif sqli_short_re.search(data) or sqli_short_re.search(url):
        return 1
    elif cmdi_re.search(data) or cmdi_re.search(url):
        return 1
    elif cmdi_simple_re.search(data) or cmdi_simple_re.search(url):
        return -1
    elif file_inclusion_re.search(data) or file_inclusion_re.search(url):
        return 1
    elif path_traversal_re.search(data) or path_traversal_re.search(url):
        return 1
    elif xxe_re.search(data) or xxe_re.search(url):
        return 1
    elif ldap_re.search(data) or ldap_re.search(url):
        return 1
    elif open_redirect_re.search(data) or open_redirect_re.search(url):
        return 1
    elif multipart_file_re.search(data) or multipart_file_re.search(url):
        return 2
    elif shell_cmds_re.search(data) or shell_cmds_re.search(url):
        return 1
    else:
        return 0

def PcapSplit():
    files = []
    bad_ips = set()
    xss_payloads = set()
    sqli_payloads = set()
    bad_domains = set()
    cmdi_payloads = set()
    pathtrav_payloads = set()
    xxe_payloads = set()
    inclusion_payloads = set()
    ldap_payloads = set()
    openredirect_payloads = set()
    bad_hashes = set()

    susp_http_ports = {8080, 8000, 8443, 8888, 3000, 5000, 81, 7080, 9080, 8008, 8090, 4443, 8180, 8181}

    txt_dir = Path(TXT_IN_DIR)
    pcap_dir = Path(PCAP_IN_DIR)
    csv_dir = Path(CSV_IN_DIR)

    def load_payload_txt(pattern, target_set):
        for file in txt_dir.rglob(pattern=pattern):
            if file.is_file():
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    target_set.update(line.strip() for line in f if line.strip())
    
    def load_payload_csv(pattern, target_set):
        for file in csv_dir.rglob(pattern=pattern):
            if file.is_file():
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    target_set.update(line.strip() for line in f if line.strip())

    load_payload_txt('xsspayload-*', xss_payloads)
    load_payload_txt('sqlipayload-*', sqli_payloads)
    load_payload_txt('maldomain-*', bad_domains)
    load_payload_txt('cmdipayload-*', cmdi_payloads)
    load_payload_txt('pathpayload-*', pathtrav_payloads)
    load_payload_txt('xxepayload-*', xxe_payloads)
    load_payload_txt('inclusionpayload-*', inclusion_payloads)
    load_payload_txt('ldappayload-*', ldap_payloads)
    load_payload_txt('openredirect-*', openredirect_payloads)
    load_payload_txt('hashpayload-*', bad_hashes)
    load_payload_csv('malip-*', bad_ips)

    bad_ips = sorted(bad_ips, key=lambda ip: ipaddress.ip_address(ip))
    
    for file_name in pcap_dir.rglob('*.pcap'):
        if file_name.is_file():
            files.append(str(file_name))

    for file in files:
        total_packets = sum(1 for _ in RawPcapReader(file))
        with PcapReader(file) as pcap_reader:
            for pkt in tqdm(pcap_reader, total=total_packets, desc=f'Analyzing packets from {os.path.basename(file)}', unit='pkt'):
                if IP not in pkt or TCP not in pkt:
                    continue

                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport

                url = ""
                body = b""

                try:
                    if pkt.haslayer(HTTPRequest):
                        http_layer = pkt[HTTPRequest]
                        url = http_layer.Path.decode(errors='ignore')
                        host = http_layer.Host.decode(errors='ignore') if http_layer.Host else ''
                        method = http_layer.Method.decode(errors='ignore')

                        payload = bytes(pkt[TCP].payload)
                        header_end = payload.find(b'\r\n\r\n')
                        body = payload[header_end + 4:] if header_end != -1 else b""

                        sha_hash = hashlib.sha256(body).hexdigest()

                        if method in ["POST", "PUT", "UPDATE"] and sha_hash in bad_hashes:
                            wrpcap(BAD_PCAP_OUT_PATH, pkt=pkt, append=True)
                            continue

                        if (host in bad_domains) or (src_ip in bad_ips) or (dst_ip in bad_ips):
                            wrpcap(BAD_PCAP_OUT_PATH, pkt=pkt, append=True)
                            continue

                        if DetectAttacks(body, url=url) == 1:
                            wrpcap(BAD_PCAP_OUT_PATH, pkt=pkt, append=True)
                            continue
                        elif DetectAttacks(body, url=url) == 2:
                            wrpcap(BAD_PCAP_OUT_PATH, pkt=pkt, append=True)
                            continue
                        elif DetectAttacks(body, url=url) == 0:
                            wrpcap(GOOD_PCAP_OUT_PATH, pkt=pkt, append=True)
                            continue

                        if any(re.search(rf"\b{x}\b", body.decode(errors="ignore"), re.IGNORECASE) for x in xxe_payloads + openredirect_payloads + cmdi_payloads + xss_payloads + sqli_payloads + pathtrav_payloads):
                            wrpcap(BAD_PCAP_OUT_PATH, pkt=pkt, append=True)
                            continue

                        if any(x in url for x in ldap_payloads + inclusion_payloads + xxe_payloads + pathtrav_payloads + cmdi_payloads + xss_payloads + sqli_payloads + openredirect_payloads):
                            wrpcap(BAD_PCAP_OUT_PATH, pkt=pkt, append=True)
                            continue

                        if src_port in susp_http_ports or dst_port in susp_http_ports:
                            wrpcap(SUSP_PCAP_OUT_PATH, pkt=pkt, append=True)
                            continue

                        wrpcap(GOOD_PCAP_OUT_PATH, pkt=pkt, append=True)
                    elif pkt.haslayer(HTTPResponse):
                        payload = bytes(pkt[TCP].payload)
                        header_end = payload.find(b'\r\n\r\n')
                        body = payload[header_end + 4:] if header_end != -1 else b""

                        sha_hash = hashlib.sha256(body).hexdigest()
                        if sha_hash in bad_hashes:
                            wrpcap(BAD_PCAP_OUT_PATH, pkt=pkt, append=True)
                        else:
                            wrpcap(GOOD_PCAP_OUT_PATH, pkt=pkt, append=True)
                except:
                    wrpcap(SUSP_PCAP_OUT_PATH, pkt=pkt, append=True)


def PcapToParquet(pcap_file, parquet_file):
    packets_data = []

    pcap_file_path = Path(pcap_file)
    if pcap_file_path.is_file() == False:
        return

    total_packets = sum(1 for _ in RawPcapReader(pcap_file))
    with PcapReader(pcap_file) as pcap_reader:
        for pkt in tqdm(pcap_reader, total=total_packets, desc=f'Processing {os.path.basename(pcap_file)}', unit='pkt'):
            try:
                if pkt.haslayer(HTTPRequest):
                    http_layer = pkt[HTTPRequest]

                    url = http_layer.Path.decode(errors='ignore')
                    host = http_layer.Host.decode(errors='ignore') if http_layer.Host else ''
                    method = http_layer.Method.decode(errors='ignore')

                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport

                    if method == 'POST' or method == 'PUT' or method == 'UPDATE':
                        payload = bytes(pkt[TCP].payload)
                        header_end = payload.find(b'\r\n\r\n')
                        body = payload[header_end + 4:] if header_end != -1 else b""

                        sha_hash = hashlib.sha256(body).hexdigest()

                        body_hex = body.hex()

                        if len(body_hex) == 0:
                            packets_data.append({
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'src_port': src_port,
                                'dst_port': dst_port,
                                'url': url,
                                'host': host,
                                'method': method,
                                'body': '',
                                'payload_hash': ''
                            })
                        else:
                            packets_data.append({
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'src_port': src_port,
                                'dst_port': dst_port,
                                'url': url,
                                'host': host,
                                'method': method,
                                'body': body_hex,
                                'payload_hash': sha_hash
                            })
                    else:
                        packets_data.append({
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'url': url,
                            'host': host,
                            'method': method,
                            'body': '',
                            'payload_hash': ''
                        })
                elif pkt.haslayer(HTTPResponse):
                    http_layer = pkt[HTTPResponse]

                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport

                    payload = bytes(pkt[TCP].payload)
                    header_end = payload.find(b'\r\n\r\n')
                    body = payload[header_end + 4:] if header_end != -1 else b""

                    sha_hash = hashlib.sha256(body).hexdigest()

                    body_hex = body.hex()

                    if len(body_hex) == 0:
                        packets_data.append({
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'url': '',
                            'host': '',
                            'method': '',
                            'body': '',
                            'payload_hash': ''
                        })
                    else:
                        packets_data.append({
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'url': '',
                            'host': '',
                            'method': '',
                            'body': body_hex,
                            'payload_hash': sha_hash
                        })
            except:
                continue
    
    data_frame = pd.DataFrame(packets_data)
    table = pa.Table.from_pandas(data_frame)
    pq.write_table(table, parquet_file)

def PcapToDataFrame(pcap_file):
    rows = []
    with PcapReader(str(pcap_file)) as pcap_reader:
        for pkt in pcap_reader:
            try:
                if pkt.haslayer(HTTPRequest):
                    http_layer = pkt[HTTPRequest]

                    url = http_layer.Path.decode(errors='ignore')
                    host = http_layer.Host.decode(errors='ignore') if http_layer.Host else ''
                    method = http_layer.Method.decode(errors='ignore')

                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport

                    payload = bytes(pkt[TCP].payload)
                    header_end = payload.find(b'\r\n\r\n')
                    body = payload[header_end + 4:] if header_end != -1 else b""

                    sha_hash = hashlib.sha256(body).hexdigest()

                    body_hex = body.hex()

                    if len(body_hex) == 0:
                        rows.append({
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'url': url,
                            'host': host,
                            'method': method,
                            'body': '',
                            'payload_hash': ''
                        })
                    else:
                        rows.append({
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'url': '',
                            'host': '',
                            'method': '',
                            'body': body_hex,
                            'payload_hash': sha_hash
                        })
                elif pkt.haslayer(HTTPResponse):
                    http_layer = pkt[HTTPResponse]

                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport

                    payload = bytes(pkt[TCP].payload)
                    header_end = payload.find(b'\r\n\r\n')
                    body = payload[header_end + 4:] if header_end != -1 else b""

                    sha_hash = hashlib.sha256(body).hexdigest()

                    body_hex = body.hex()

                    if len(body_hex) == 0:
                        rows.append({
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'url': '',
                            'host': '',
                            'method': '',
                            'body': '',
                            'payload_hash': ''
                        })
                    else:
                        rows.append({
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'url': '',
                            'host': '',
                            'method': '',
                            'body': body_hex,
                            'payload_hash': sha_hash
                        })
            except:
                continue

    return pd.DataFrame(rows)