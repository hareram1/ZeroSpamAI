# ------------------------
# Step 1: Import Libraries
# ------------------------
import pandas as pd
import tldextract
import re
import whois
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib
import json
import matplotlib.pyplot as plt

# ------------------------
# Step 2: Data Preprocessing
# ------------------------
# Load raw data
data = pd.read_csv("data/raw/url_data.csv")

# ------------------------
# New Feature Extraction Functions
# ------------------------
def get_domain_age(url):
    try:
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        if not domain: return 730  # Default 2 years
        
        w = whois.query(domain)
        if w and w.creation_date:
            if isinstance(w.creation_date, list):
                creation_date = w.creation_date[0]
            else:
                creation_date = w.creation_date
            return (datetime.now() - creation_date).days
    except:
        return 730  # Return default if WHOIS fails
    return 730

def contains_ip(url):
    return 1 if re.match(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url) else 0

def has_non_standard_port(url):
    return 1 if re.search(r":\d{2,5}/", url) else 0

def suspicious_tld(url):
    tlds = ['.xyz', '.top', '.loan', '.click', '.gq', '.tk']
    extracted = tldextract.extract(url)
    return 1 if f".{extracted.suffix}" in tlds else 0

# ------------------------
# Feature Extraction
# ------------------------
# Existing Features
data["url_length"] = data["url"].apply(len)
data["has_https"] = data["url"].apply(lambda x: 1 if x.startswith("https://") else 0)
data["num_subdomains"] = data["url"].apply(lambda x: len(tldextract.extract(x).subdomain.split('.')) if tldextract.extract(x).subdomain else 0)
data["has_special_char"] = data["url"].apply(lambda x: 1 if any(c in x for c in ['@', '-', '_']) else 0)
data["is_shortened"] = data["url"].apply(lambda x: 1 if any(s in x for s in ["bit.ly", "tinyurl", "goo.gl"]) else 0)

# New Features
data["domain_age"] = data["url"].apply(get_domain_age)
data["contains_ip"] = data["url"].apply(contains_ip)
data["has_port"] = data["url"].apply(has_non_standard_port)
data["suspicious_tld"] = data["url"].apply(suspicious_tld)

# Save preprocessed data
data.to_csv("data/processed/preprocessed_data.csv", index=False)
print("Preprocessing done! File saved: data/processed/preprocessed_data.csv")

# ------------------------
# Step 3: Split Data
# ------------------------
X = data.drop(["url", "status"], axis=1)
y = data["status"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print(f"\nTraining data shape: {X_train.shape}")
print(f"Testing data shape: {X_test.shape}")

# ------------------------
# Step 4: Check Class Balance
# ------------------------
print("\nClass Distribution:")
print("Original Data:", y.value_counts(normalize=True).round(2))
print("Training Data:", y_train.value_counts(normalize=True).round(2))
print("Testing Data:", y_test.value_counts(normalize=True).round(2))

# ------------------------
# Step 5: Train the Model
# ------------------------
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

print("\nTraining the model...")
model.fit(X_train, y_train)

# ------------------------
# Step 6: Evaluate the Model
# ------------------------
y_pred = model.predict(X_test)

print("\nModel Performance:")
print(f"Accuracy: {accuracy_score(y_test, y_pred):.2f}")
print(f"Precision: {precision_score(y_test, y_pred):.2f}")
print(f"Recall: {recall_score(y_test, y_pred):.2f}") 
print(f"F1 Score: {f1_score(y_test, y_pred):.2f}")

# ------------------------
# Step 7: Save Model & Features
# ------------------------
joblib.dump(model, "models/best_model.pkl")
print("\nModel saved: models/best_model.pkl")

# Save feature list for reference
with open("models/feature_list.txt", "w") as f:
    f.write("\n".join(X.columns.tolist()))

# ------------------------
# Feature Importance Plot
# ------------------------
plt.figure(figsize=(10, 6))
plt.barh(X.columns, model.feature_importances_)
plt.title("Feature Importance")
plt.savefig("models/feature_importance.png", bbox_inches="tight")
print("\nFeature importance plot saved: models/feature_importance.png")

# ------------------------
# Save feature order
# ------------------------
feature_order = X.columns.tolist()
with open("models/feature_order.json", "w") as f:
    json.dump(feature_order, f)