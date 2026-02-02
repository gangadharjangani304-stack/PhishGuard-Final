import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

# LOAD DATASET
# Ensure 'phishing.csv' is in the dataset folder
try:
    data = pd.read_csv('dataset/phishing.csv')
except FileNotFoundError:
    print("❌ Dataset not found. Please download it first.")
    exit()

# SELECT FEATURES (Must match FeatureExtractor)
# These are standard column names in the Kaggle Dataset
selected_features = [
    'having_IPhaving_IP_Address', 
    'URL_Length', 
    'Shortining_Service', 
    'having_At_Symbol', 
    'double_slash_redirecting', 
    'Prefix_Suffix', 
    'having_Sub_Domain', 
    'HTTPS_token', 
    'Request_URL', 
    'URL_of_Anchor',
    'Result'
]

# Check if columns exist
try:
    df = data[selected_features]
except KeyError:
    print("❌ Column mismatch. Check CSV headers.")
    exit()

# PREPARE DATA
X = df.drop('Result', axis=1)
y = df['Result']

# TRAIN
print("🚀 Training Random Forest Model...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
rf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42)
rf.fit(X_train, y_train)

# EVALUATE
preds = rf.predict(X_test)
acc = accuracy_score(y_test, preds)
print(f"✅ Model Accuracy: {acc * 100:.2f}%")

# SAVE
joblib.dump(rf, 'model.pkl')
print("💾 Model saved as 'model.pkl'")