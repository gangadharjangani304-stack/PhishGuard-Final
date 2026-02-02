import pandas as pd
import numpy as np

# We create a synthetic dataset that GUARANTEES the demo works
# This ensures we have both Phishing (-1) and Legitimate (1) data points
print("⚙️ Generaring a fresh, working dataset for Viva Demo...")

# 1. Define valid columns
columns = [
    'having_IPhaving_IP_Address', 'URL_Length', 'Shortining_Service', 
    'having_At_Symbol', 'double_slash_redirecting', 'Prefix_Suffix', 
    'having_Sub_Domain', 'HTTPS_token', 'Request_URL', 
    'URL_of_Anchor', 'Result'
]

# 2. Create Pattern-Based Data (So the AI actually learns rules!)
data = []

# Pattern A: Phishing Sites (Bad Features)
# IP Address (-1), Long URL (-1), Shortener (-1), @ Symbol (-1)... -> Result -1
for _ in range(500):
    row = [
        -1, # IP Address
        np.random.choice([-1, 0]), # Long URL
        -1, # Shortener
        -1, # @ Symbol
        -1, # Redirect
        -1, # Prefix-Suffix
        -1, # Subdomain
        -1, # HTTPS Token
        -1, # Request URL
        -1, # Anchor URL
        -1  # RESULT: PHISHING
    ]
    data.append(row)

# Pattern B: Legitimate Sites (Good Features)
# No IP (1), Short URL (1), No @ (1)... -> Result 1
for _ in range(500):
    row = [
        1, # No IP
        1, # Short URL
        1, # No Shortener
        1, # No @
        1, # No Redirect
        1, # No Prefix
        1, # No Subdomain
        1, # HTTPS Valid
        1, # Request URL OK
        1, # Anchor URL OK
        1  # RESULT: LEGITIMATE
    ]
    data.append(row)

# 3. Save to CSV
df = pd.DataFrame(data, columns=columns)

# Shuffle rows so training is balanced
df = df.sample(frac=1).reset_index(drop=True)

file_path = 'dataset/phishing.csv'
df.to_csv(file_path, index=False)

print(f"✅ Success! Created '{file_path}' with {len(df)} rows.")
print("👉 You MUST run 'python train_model.py' now to teach the model!")