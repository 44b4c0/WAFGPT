import subprocess
import json
import os

from config import LLAMA_CPP_MODEL_PATH, LLAMA_CPP_CLI_PATH

def AssemblePrompt(parquet_data):
    prompt = f"""
    You are a cybersecurity packet analyzer.
    Classify each packet below into one of three categories:

    - GOOD → normal traffic
    - SUS → suspicious but not confirmed malicious
    - BAD → definitely malicious or attack traffic

    Return JSON only in this exact format:
    [{{"id": <packet_id>, "class": "<GOOD/SUS/BAD>"}}]

    Packets:
    {parquet_data}
    """

    return prompt

def FormatPacket(row, idx):
    return (
        f"[{idx}] "
        f"src={row['src_ip']}:{row['src_port']} -> dst={row['dst_ip']}:{row['dst_port']} | "
        f"method={row['method']} host={row['host']} url={row['url']} | "
        f"body={row.get('body', '')} | "
        f"payload_hash={row.get('payload_hash', '')}"
    )

def AnalyzeParquet(data):
    parquet_data = '\n'.join(FormatPacket(row, idx) for idx, row in data.iterrows())
    
    prompt = AssemblePrompt(parquet_data=parquet_data)

    command = [
        LLAMA_CPP_CLI_PATH,
        "-m", LLAMA_CPP_MODEL_PATH,
        "--prompt", prompt,
        "--n_ctx", "8192",
        "--temp", "0.1",
        "--max_tokens", "512",
        "--ggml-cuda"
    ]
    proc = subprocess.run(
        command,
        capture_output=True,
        text=True,
        env=os.environ.copy()
    )

    if proc.returncode != 0:
        return []
    
    text = proc.stdout
    try:
        start = text.find("[")
        end = text.rfind("]") + 1
        json_part = text[start:end]
        return json.loads(json_part)
    except:
        return []