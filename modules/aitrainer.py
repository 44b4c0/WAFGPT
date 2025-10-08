from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from torch.utils.data import Dataset, DataLoader
from torch.utils.data import Dataset
import torch.nn.functional as F
from pathlib import Path
import torch.nn as nn
from tqdm import tqdm
import torch.nn as nn
import pandas as pd
import joblib
import base64
import torch
import os

from config import PCAP_GUESS_IN_DIR, EPOCH_NUMS, MODEL_OUT_PATH, VECTORIZER_OUT_PATH
from modules.dataparser import PcapToDataFrame

def LoadParquet(file, label):
    if os.path.exists(file) and os.path.getsize(file) > 0:
        parquet_file = pd.read_parquet(file)
        parquet_file['label'] = label
        return parquet_file
    else:
        return pd.DataFrame(columns=["src_ip","dst_ip","src_port","dst_port","url","host","method","body","body_hash","label"])

class TrafficDataset(Dataset):
    def __init__(self, x, y):
        # self.x = torch.tensor(x, dtype=torch.float32)
        # self.y = torch.tensor(y, dtype=torch.long)
        self.x = x
        self.y = y
    
    def __len__(self):
        return self.x.shape[0]
    
    def __getitem__(self, idx):
        # return self.x[idx], self.y[idx]
        x_dense = self.x[idx].toarray().squeeze()
        y_value = self.y[idx]
        return torch.tensor(x_dense, dtype=torch.float32), torch.tensor(y_value, dtype=torch.long)

class TrafficClassifier(nn.Module):
    def __init__(self, input_dim, number_classes):
        super().__init__()
        self.fc1 = nn.Linear(input_dim, 512)
        self.fc2 = nn.Linear(512, 128)
        self.fc3 = nn.Linear(128, number_classes)
        self.dropout = nn.Dropout(0.3)
    
    def forward(self, x):
        x = F.relu(self.fc1(x))
        x = self.dropout(x)
        x = F.relu(self.fc2(x))
        x = self.dropout(x)
        return self.fc3(x)

def Base64ToHex(data):
    try:
        return base64.b64decode(data).hex()
    except:
        return ''

# Training model
def TrainModel(concatinated):
    concatinated.fillna('', inplace=True)
    concatinated['body'] = concatinated['body'].apply(Base64ToHex)
    concatinated['text'] = concatinated['method'] + ' ' + concatinated['host'] + ' ' + concatinated['url'] + ' ' + concatinated['body']
    labels = concatinated['label'].astype('category').cat.codes
    number_classes = 3

    vectorizer = TfidfVectorizer(max_features=10000, ngram_range=(1, 2))
    # x = vectorizer.fit_transform(concatinated['text']).toarray()
    x = vectorizer.fit_transform(concatinated['text'])
    y = labels.values

    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)
    train_dataset = TrafficDataset(x_train, y_train)
    test_dataset = TrafficDataset(x_test, y_test)

    train_dataloader = DataLoader(train_dataset, batch_size=64, shuffle=True)
    test_dataloader = DataLoader(test_dataset, batch_size=64)

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model = TrafficClassifier(x.shape[1], number_classes).to(device=device)

    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    criterion = nn.CrossEntropyLoss()

    for epoch in range(EPOCH_NUMS):
        model.train()
        total_loss = 0

        progress_bar = tqdm(train_dataloader, desc=f'Epoch {epoch + 1}/{EPOCH_NUMS}', leave=False)
        for xb, yb in progress_bar:
            xb, yb = xb.to(device), yb.to(device)
            optimizer.zero_grad()

            preds = model(xb)
            loss = criterion(preds, yb)
            loss.backward()

            optimizer.step()
            total_loss += loss.item()
            progress_bar.set_postfix({"loss": total_loss / (progress_bar.n + 1)})

    model.eval()
    correct = total = 0
    with torch.no_grad():
        for xb, yb in test_dataloader:
            xb, yb = xb.to(device), yb.to(device)
            preds = model(xb)
            predicted = preds.argmax(1)
            total += yb.size(0)
            correct += (predicted == yb).sum().item()

    torch.save(model.state_dict(), MODEL_OUT_PATH)
    joblib.dump(vectorizer, VECTORIZER_OUT_PATH)

# Loading model
def LoadModel():
    vectorizer = joblib.load(VECTORIZER_OUT_PATH)

    input_dim = len(vectorizer.get_feature_names_out())
    number_classes = 3
    model = TrafficClassifier(input_dim, number_classes)

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model.load_state_dict(torch.load(MODEL_OUT_PATH, map_location=device))
    model.to(device)
    model.eval()

    pcap_in_dir = Path(PCAP_GUESS_IN_DIR)

    loaded_dfs = []

    for pcap_file in tqdm(list(pcap_in_dir.glob('*.pcap')), desc='Loading PCAP files'):
        loaded_df = PcapToDataFrame(pcap_file)
        if loaded_df.empty:
            continue

        loaded_df.fillna('', inplace=True)
        loaded_df['text'] = loaded_df['method'] + ' ' + loaded_df['host'] + ' ' + loaded_df['url'] + ' ' + loaded_df['body']

        x = vectorizer.transform(loaded_df['text']).toarray()
        x_tensor = torch.tensor(x, dtype=torch.float32).to(device)

        with torch.no_grad():
            outputs = model(x_tensor)
            preds = torch.argmax(outputs, dim=1).cpu().numpy()

        label_map = {0: 'good', 1: 'bad', 2: 'sus'}
        loaded_df['prediction'] = [label_map[p] for p in preds]

        loaded_dfs.append(loaded_df)

    results = pd.concat(loaded_dfs, ignore_index=True)

    if 'bad' in results['prediction'].values or 'sus' in results['prediction'].values:
        bad_count = (results['prediction'] == 'bad').sum()
        sus_count = (results['prediction'] == 'sus').sum()
        print(f'Bad: {bad_count} packets, Suspicious: {sus_count} packets')
    else:
        print('Bad: 0 packets, Suspicious: 0 packets')
    
    return results