import pandas as pd
import numpy as np
import lightgbm as lgb
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    classification_report, accuracy_score, roc_auc_score,
    confusion_matrix, f1_score, recall_score, precision_score,
    roc_curve, auc, precision_recall_curve, average_precision_score
)
from sklearn.base import BaseEstimator, ClassifierMixin
import joblib
from tqdm import tqdm
import warnings
import re
from urllib.parse import urlparse
from scipy.sparse import hstack
import math
import matplotlib.pyplot as plt
import seaborn as sns

warnings.filterwarnings("ignore")


# ==================== FEATURE ENGINEERING ====================

def calculate_entropy(text):
    """Tính entropy của chuỗi"""
    if not text:
        return 0
    entropy = 0
    for x in range(256):
        p_x = text.count(chr(x)) / len(text)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy


def extract_url_features(url):
    """Trích xuất 30+ đặc trưng từ URL"""
    features = {}

    try:
        parsed = urlparse(str(url))
        domain = parsed.netloc
        path = parsed.path

        # === Đặc trưng cơ bản ===
        features['url_length'] = len(url)
        features['domain_length'] = len(domain)
        features['path_length'] = len(path)
        features['query_length'] = len(parsed.query)

        # === Đếm ký tự đặc biệt ===
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_questions'] = url.count('?')
        features['num_equals'] = url.count('=')
        features['num_at'] = url.count('@')
        features['num_ampersands'] = url.count('&')
        features['num_percent'] = url.count('%')
        features['num_digits'] = sum(c.isdigit() for c in url)

        # === Đặc trưng nghi ngờ ===
        features['has_ip'] = int(bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)))
        features['has_port'] = int(bool(re.search(r':\d{2,5}', url)))
        features['has_double_slash_redirect'] = int('//' in path)
        features['has_prefix_suffix'] = int('-' in domain)

        # === TLD nghi ngờ ===
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click']
        features['suspicious_tld'] = int(any(url.endswith(tld) for tld in suspicious_tlds))

        # === HTTPS ===
        features['is_https'] = int(parsed.scheme == 'https')

        # === Độ phức tạp ===
        features['entropy'] = calculate_entropy(url)
        features['domain_entropy'] = calculate_entropy(domain)

        # === Subdomain ===
        subdomain_count = domain.count('.') - 1
        features['subdomain_count'] = subdomain_count if subdomain_count >= 0 else 0
        features['has_subdomain'] = int(subdomain_count > 0)

        # === Path depth ===
        features['path_depth'] = path.count('/')

        # === Từ khóa nghi ngờ ===
        suspicious_keywords = [
            'login', 'signin', 'account', 'verify', 'secure', 'update',
            'bank', 'paypal', 'wallet', 'password', 'confirm'
        ]
        features['suspicious_keywords'] = sum(1 for kw in suspicious_keywords if kw in url.lower())

        # === Tỷ lệ ===
        features['digit_ratio'] = features['num_digits'] / max(len(url), 1)
        features['special_char_ratio'] = (
                                                 features['num_hyphens'] + features['num_underscores'] +
                                                 features['num_at'] + features['num_percent']
                                         ) / max(len(url), 1)

        # === Độ dài bất thường ===
        features['abnormal_url'] = int(len(url) > 75)
        features['abnormal_domain'] = int(len(domain) > 30)

    except Exception as e:
        # Nếu URL không parse được, đánh dấu là nghi ngờ
        for key in ['url_length', 'domain_length', 'path_length', 'query_length',
                    'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
                    'num_questions', 'num_equals', 'num_at', 'num_ampersands',
                    'num_percent', 'num_digits', 'has_ip', 'has_port',
                    'has_double_slash_redirect', 'has_prefix_suffix', 'suspicious_tld',
                    'is_https', 'entropy', 'domain_entropy', 'subdomain_count',
                    'has_subdomain', 'path_depth', 'suspicious_keywords',
                    'digit_ratio', 'special_char_ratio', 'abnormal_url', 'abnormal_domain']:
            features[key] = 0
        features['parse_error'] = 1
        features['suspicious_tld'] = 1

    return features


def create_feature_matrix(urls, vectorizer=None, fit=False):
    """Tạo ma trận đặc trưng kết hợp TF-IDF và handcrafted features"""
    print("🔹 Trích xuất handcrafted features...")
    handcrafted = pd.DataFrame([extract_url_features(url) for url in tqdm(urls, desc="Features")])

    print("🔹 Trích xuất TF-IDF features...")
    if fit:
        vectorizer = TfidfVectorizer(
            max_features=8000,
            token_pattern=r"(?u)\b\w+\b",
            ngram_range=(1, 3),
            min_df=2
        )
        tfidf_features = vectorizer.fit_transform(urls.progress_apply(str))
    else:
        tfidf_features = vectorizer.transform(urls.progress_apply(str))

    # Kết hợp features
    combined = hstack([tfidf_features, handcrafted.values])

    return combined, vectorizer, handcrafted.columns.tolist()


# ==================== DATA LOADING & CLEANING ====================

print("=" * 70)
print("🚀 ADVANCED URL PHISHING DETECTION MODEL")
print("=" * 70)

print("\n🔹 Đang đọc và hợp nhất dữ liệu...")

files = [
    "malicious_phish.csv",
    "data.csv",
    "Malicious-URLs.csv",
    "cleaned_topreal_urls.csv",
    "new_data_urls.csv",
    "urldata.csv",
    "phishing_site_urls.csv",
]

dfs = []
for f in files:
    try:
        df = pd.read_csv(f, low_memory=False)

        # Chuẩn hóa tên cột
        if 'URL' in df.columns and 'url' not in df.columns:
            df.rename(columns={'URL': 'url'}, inplace=True)

        if 'type' in df.columns and 'label' not in df.columns:
            df.rename(columns={'type': 'label'}, inplace=True)
        elif 'Label' in df.columns and 'label' not in df.columns:
            df.rename(columns={'Label': 'label'}, inplace=True)
        elif 'status' in df.columns and 'label' not in df.columns:
            df.rename(columns={'status': 'label'}, inplace=True)

        if 'url' in df.columns and 'label' in df.columns:
            df = df[['url', 'label']]
            print(f"   → {f}: {len(df):,} hàng ✓")
            dfs.append(df)
        elif 'url' in df.columns and 'label' not in df.columns:
            if 'cleaned_topreal' in f.lower() or 'clean' in f.lower():
                df['label'] = 0
                df = df[['url', 'label']]
                print(f"   → {f}: {len(df):,} hàng ✓ (tự động gán nhãn BENIGN)")
                dfs.append(df)
            else:
                print(f"   ⚠️ {f}: Có 'url' nhưng KHÔNG có cột nhãn → Bỏ qua")
        else:
            print(f"   ⚠️ {f}: Thiếu cột 'url' → Bỏ qua")

    except Exception as e:
        print(f"⚠️ Không đọc được {f}: {e}")

if not dfs:
    raise ValueError("❌ Không có dữ liệu nào được đọc thành công!")

data = pd.concat(dfs, ignore_index=True)
print(f"\n✅ Dữ liệu hợp nhất: {len(data):,} hàng")

# ==================== DATA CLEANING ====================

print("\n🔹 Làm sạch dữ liệu...")

if 'url' not in data.columns or 'label' not in data.columns:
    raise ValueError("❌ Thiếu cột 'url' hoặc 'label'!")

before = len(data)
data = data[data['url'].notna() & data['label'].notna()]
print(f"   → Loại bỏ {before - len(data):,} hàng thiếu dữ liệu")

print("\n🔹 Phân tích nhãn:")
print(data['label'].value_counts())

MALICIOUS_LABELS = {'malicious', 'phishing', 'defacement', 'bad', '1', 1, 'spam', 'malware'}
BENIGN_LABELS = {'benign', 'legitimate', 'safe', 'good', '0', 0}


def standardize_label(x):
    x_str = str(x).lower().strip()
    if x_str in MALICIOUS_LABELS:
        return 1
    elif x_str in BENIGN_LABELS:
        return 0
    return None


data['label'] = data['label'].apply(standardize_label)
before = len(data)
data = data.dropna(subset=['label'])
print(f"   → Loại bỏ {before - len(data):,} nhãn không hợp lệ")

data['label'] = data['label'].astype(int)

data = data[data['url'].str.len() > 10]
data = data[data['url'].str.contains(r'[a-zA-Z]')]

before = len(data)
data = data.drop_duplicates(subset=['url'], keep='first')
print(f"   → Loại bỏ {before - len(data):,} URL trùng lặp")

print(f"\n✅ Dữ liệu sau khi làm sạch: {len(data):,} hàng")
print(f"   → Malicious: {(data['label'] == 1).sum():,} ({(data['label'] == 1).mean() * 100:.1f}%)")
print(f"   → Benign: {(data['label'] == 0).sum():,} ({(data['label'] == 0).mean() * 100:.1f}%)")

if len(data) > 400_000:
    print(f"\n⚠️ Giới hạn 400.000 hàng để tăng tốc (stratified sampling)")
    data = data.groupby('label', group_keys=False).apply(
        lambda x: x.sample(min(len(x), 200_000), random_state=42)
    ).reset_index(drop=True)

# ==================== FEATURE EXTRACTION ====================

print("\n" + "=" * 70)
print("🔹 TRÍCH XUẤT ĐẶC TRƯNG")
print("=" * 70)

X_train, X_test, y_train, y_test = train_test_split(
    data['url'],
    data['label'],
    test_size=0.2,
    random_state=42,
    stratify=data['label']
)

print(f"\nTrain set: {len(X_train):,} | Test set: {len(X_test):,}")

tqdm.pandas()
X_train_features, vectorizer, feature_names = create_feature_matrix(X_train, fit=True)
X_test_features, _, _ = create_feature_matrix(X_test, vectorizer=vectorizer, fit=False)

print(f"\n✅ Kích thước ma trận đặc trưng: {X_train_features.shape}")
print(f"   → TF-IDF features: 8000")
print(f"   → Handcrafted features: {len(feature_names)}")

# ==================== MODEL TRAINING ====================

print("\n" + "=" * 70)
print("🔹 HUẤN LUYỆN MÔ HÌNH LIGHTGBM")
print("=" * 70)

params = {
    "objective": "binary",
    "metric": "auc",
    "boosting_type": "gbdt",
    "num_leaves": 31,
    "max_depth": 7,
    "learning_rate": 0.05,
    "feature_fraction": 0.8,
    "bagging_fraction": 0.8,
    "bagging_freq": 5,
    "lambda_l1": 0.1,
    "lambda_l2": 0.1,
    "min_data_in_leaf": 20,
    "min_gain_to_split": 0.01,
    "verbose": -1,
    "n_jobs": -1
}

train_data = lgb.Dataset(X_train_features, label=y_train)
valid_data = lgb.Dataset(X_test_features, label=y_test, reference=train_data)

print("\n🚀 Bắt đầu huấn luyện...")
model = lgb.train(
    params,
    train_data,
    valid_sets=[train_data, valid_data],
    valid_names=['train', 'valid'],
    num_boost_round=500,
    callbacks=[
        lgb.early_stopping(stopping_rounds=30),
        lgb.log_evaluation(period=20)
    ]
)

print(f"\n✅ Huấn luyện hoàn tất!")
print(f"   → Best iteration: {model.best_iteration}")
print(f"   → Best AUC: {model.best_score['valid']['auc']:.4f}")

# ==================== BASIC EVALUATION ====================

print("\n" + "=" * 70)
print("🔹 ĐÁNH GIÁ CÁ BẢN")
print("=" * 70)

y_pred_prob = model.predict(X_test_features, num_iteration=model.best_iteration)

thresholds = [0.3, 0.4, 0.5, 0.6, 0.7]
best_threshold = 0.5
best_f1 = 0

print("\n📊 Tìm threshold tối ưu:")
for thresh in thresholds:
    y_pred_temp = (y_pred_prob > thresh).astype(int)
    f1 = f1_score(y_test, y_pred_temp)
    recall = recall_score(y_test, y_pred_temp)
    precision = precision_score(y_test, y_pred_temp)
    print(f"   Threshold {thresh:.1f}: F1={f1:.4f}, Recall={recall:.4f}, Precision={precision:.4f}")

    if f1 > best_f1:
        best_f1 = f1
        best_threshold = thresh

print(f"\n✅ Threshold tốt nhất: {best_threshold}")

y_pred = (y_pred_prob > best_threshold).astype(int)

print("\n" + "=" * 70)
print("📈 KẾT QUẢ CƠ BẢN")
print("=" * 70)

print(f"\n🎯 Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print(f"🎯 AUC-ROC: {roc_auc_score(y_test, y_pred_prob):.4f}")
print(f"🎯 F1-Score: {f1_score(y_test, y_pred):.4f}")
print(f"🎯 Precision: {precision_score(y_test, y_pred):.4f}")
print(f"🎯 Recall: {recall_score(y_test, y_pred):.4f}")

cm = confusion_matrix(y_test, y_pred)
print(f"\n📊 Confusion Matrix:")
print(f"   True Negatives:  {cm[0, 0]:,}")
print(f"   False Positives: {cm[0, 1]:,} (False alarms)")
print(f"   False Negatives: {cm[1, 0]:,} (Missed attacks) ⚠️")
print(f"   True Positives:  {cm[1, 1]:,}")

print("\n📋 Classification Report:")
print(classification_report(y_test, y_pred, target_names=['Benign', 'Malicious']))

# ==================== ADVANCED EVALUATION ====================

print("\n" + "=" * 70)
print("🔍 ĐÁNH GIÁ CHI TIẾT MÔ HÌNH")
print("=" * 70)

# 1. ROC Curve
fpr, tpr, thresholds_roc = roc_curve(y_test, y_pred_prob)
roc_auc = auc(fpr, tpr)

plt.figure(figsize=(10, 6))
plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.4f})')
plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', label='Random Classifier')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate', fontsize=12)
plt.ylabel('True Positive Rate (Recall)', fontsize=12)
plt.title('ROC Curve - Phishing Detection Model', fontsize=14, fontweight='bold')
plt.legend(loc="lower right", fontsize=11)
plt.grid(alpha=0.3)
plt.tight_layout()
plt.savefig('roc_curve.png', dpi=300, bbox_inches='tight')
print("\n✅ Đã lưu: roc_curve.png")
plt.close()

# 2. Precision-Recall Curve
precision_vals, recall_vals, thresholds_pr = precision_recall_curve(y_test, y_pred_prob)
avg_precision = average_precision_score(y_test, y_pred_prob)

plt.figure(figsize=(10, 6))
plt.plot(recall_vals, precision_vals, color='blue', lw=2,
         label=f'PR curve (AP = {avg_precision:.4f})')
plt.axhline(y=(y_test == 1).mean(), color='red', linestyle='--',
            label=f'Baseline = {(y_test == 1).mean():.3f}')
plt.xlabel('Recall', fontsize=12)
plt.ylabel('Precision', fontsize=12)
plt.title('Precision-Recall Curve', fontsize=14, fontweight='bold')
plt.legend(loc="best", fontsize=11)
plt.grid(alpha=0.3)
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.tight_layout()
plt.savefig('precision_recall_curve.png', dpi=300, bbox_inches='tight')
print("✅ Đã lưu: precision_recall_curve.png")
plt.close()

# 3. Confusion Matrix Heatmap
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=True,
            xticklabels=['Benign', 'Malicious'],
            yticklabels=['Benign', 'Malicious'],
            annot_kws={"size": 14, "weight": "bold"})
plt.title('Confusion Matrix', fontsize=14, fontweight='bold')
plt.ylabel('True Label', fontsize=12)
plt.xlabel('Predicted Label', fontsize=12)
plt.tight_layout()
plt.savefig('confusion_matrix.png', dpi=300, bbox_inches='tight')
print("✅ Đã lưu: confusion_matrix.png")
plt.close()

# 4. Error Analysis
print("\n" + "=" * 70)
print("⚠️ PHÂN TÍCH SAI SỐ")
print("=" * 70)

fp_indices = np.where((y_test.values == 0) & (y_pred == 1))[0]
if len(fp_indices) > 0:
    print(f"\n🔸 FALSE POSITIVES: {len(fp_indices):,} trường hợp")
    print("   (URL lành tính bị cảnh báo nhầm)")
    fp_urls = X_test.iloc[fp_indices].head(5)
    fp_probs = y_pred_prob[fp_indices][:5]
    for url, prob in zip(fp_urls, fp_probs):
        print(f"   → {url[:70]} (Confidence: {prob:.2%})")

fn_indices = np.where((y_test.values == 1) & (y_pred == 0))[0]
if len(fn_indices) > 0:
    print(f"\n🔸 FALSE NEGATIVES: {len(fn_indices):,} trường hợp ⚠️⚠️⚠️")
    print("   (URL độc hại BỊ BỎ LỠ - RẤT NGUY HIỂM!)")
    fn_urls = X_test.iloc[fn_indices].head(5)
    fn_probs = y_pred_prob[fn_indices][:5]
    for url, prob in zip(fn_urls, fn_probs):
        print(f"   → {url[:70]} (Confidence: {prob:.2%})")

# 5. Confidence Distribution
print("\n" + "=" * 70)
print("📊 PHÂN BỐ CONFIDENCE SCORE")
print("=" * 70)

bins = [0, 0.2, 0.4, 0.6, 0.8, 1.0]
bin_labels = ['0-20%', '20-40%', '40-60%', '60-80%', '80-100%']

for i in range(len(bins) - 1):
    mask = (y_pred_prob >= bins[i]) & (y_pred_prob < bins[i + 1])
    if mask.sum() > 0:
        accuracy_bin = accuracy_score(y_test[mask], y_pred[mask])
        print(f"   {bin_labels[i]}: {mask.sum():5,} mẫu | Accuracy: {accuracy_bin:.4f}")

# 6. Cross-Validation
print("\n" + "=" * 70)
print("🔄 CROSS-VALIDATION (5-FOLD)")
print("=" * 70)

if len(X_train) > 50000:
    from scipy.sparse import csr_matrix

    X_train_features = X_train_features.tocsr()
    print("⚠️ Giới hạn 50k mẫu cho CV (tốc độ)")
    cv_indices = np.random.choice(len(X_train), 50000, replace=False)
    X_cv = X_train_features[cv_indices]
    y_cv = y_train.iloc[cv_indices]
else:
    X_cv = X_train_features
    y_cv = y_train


class LGBMWrapper(BaseEstimator, ClassifierMixin):
    def __init__(self, params):
        self.params = params
        self.model = None

    def fit(self, X, y):
        train_data = lgb.Dataset(X, label=y)
        self.model = lgb.train(self.params, train_data, num_boost_round=100, verbose_eval=False)
        return self

    def predict_proba(self, X):
        pred = self.model.predict(X)
        return np.vstack([1 - pred, pred]).T

    def predict(self, X):
        return (self.predict_proba(X)[:, 1] > 0.5).astype(int)


lgbm_cv = LGBMWrapper(params)
cv_scores = cross_val_score(lgbm_cv, X_cv, y_cv, cv=5, scoring='roc_auc', n_jobs=-1)

print(f"\n📈 Cross-Validation AUC Scores:")
for i, score in enumerate(cv_scores, 1):
    print(f"   Fold {i}: {score:.4f}")
print(f"\n   Mean AUC: {cv_scores.mean():.4f} (±{cv_scores.std():.4f})")

# 7. Class-specific Metrics
print("\n" + "=" * 70)
print("📊 CHỈ SỐ THEO TỪNG LỚP")
print("=" * 70)

benign_mask = y_test == 0
benign_correct = (y_pred[benign_mask] == 0).sum()
benign_total = benign_mask.sum()
benign_accuracy = benign_correct / benign_total

malicious_mask = y_test == 1
malicious_correct = (y_pred[malicious_mask] == 1).sum()
malicious_total = malicious_mask.sum()
malicious_accuracy = malicious_correct / malicious_total

print(f"\n🟢 BENIGN URLs:")
print(f"   Total: {benign_total:,}")
print(f"   Correctly classified: {benign_correct:,} ({benign_accuracy:.2%})")
print(f"   Misclassified: {benign_total - benign_correct:,} ({1 - benign_accuracy:.2%})")

print(f"\n🔴 MALICIOUS URLs:")
print(f"   Total: {malicious_total:,}")
print(f"   Correctly detected: {malicious_correct:,} ({malicious_accuracy:.2%})")
print(f"   Missed: {malicious_total - malicious_correct:,} ({1 - malicious_accuracy:.2%}) ⚠️")

# 8. Learning Curve
print("\n" + "=" * 70)
print("📈 LEARNING CURVE ANALYSIS")
print("=" * 70)

train_sizes = [0.1, 0.3, 0.5, 0.7, 0.9]
train_scores = []
test_scores = []

for size in train_sizes:
    n_samples = int(len(X_train) * size)
    indices = np.random.choice(len(X_train), n_samples, replace=False)

    X_subset = X_train_features[indices]
    y_subset = y_train.iloc[indices]

    train_data_subset = lgb.Dataset(X_subset, label=y_subset)
    model_subset = lgb.train(params, train_data_subset, num_boost_round=100, verbose_eval=False)

    train_pred = model_subset.predict(X_subset)
    test_pred = model_subset.predict(X_test_features)

    train_auc = roc_auc_score(y_subset, train_pred)
    test_auc = roc_auc_score(y_test, test_pred)

    train_scores.append(train_auc)
    test_scores.append(test_auc)

    print(f"   {size:.0%} data: Train AUC={train_auc:.4f} | Test AUC={test_auc:.4f}")

plt.figure(figsize=(10, 6))
plt.plot([s * 100 for s in train_sizes], train_scores, 'o-', color='blue', label='Training AUC')
plt.plot([s * 100 for s in train_sizes], test_scores, 'o-', color='red', label='Validation AUC')
plt.xlabel('Training Set Size (%)', fontsize=12)
plt.ylabel('AUC Score', fontsize=12)
plt.title('Learning Curve', fontsize=14, fontweight='bold')
plt.legend(loc='best', fontsize=11)
plt.grid(alpha=0.3)
plt.tight_layout()
plt.savefig('learning_curve.png', dpi=300, bbox_inches='tight')
print("\n✅ Đã lưu: learning_curve.png")
plt.close()

# 9. Feature Importance
print("\n🔝 Top 20 đặc trưng quan trọng nhất:")
importance = model.feature_importance(importance_type='gain')
all_feature_names = ['tfidf_' + str(i) for i in range(8000)] + feature_names
feature_imp = pd.DataFrame({
    'feature': all_feature_names,
    'importance': importance
}).sort_values('importance', ascending=False)

for idx, row in feature_imp.head(20).iterrows():
    print(f"   {row['feature'][:40]:<40} → {row['importance']:.0f}")

# 10. Summary Report
print("\n" + "=" * 70)
print("📄 BÁO CÁO TỔNG KẾT")
print("=" * 70)

report = f"""
╔══════════════════════════════════════════════════════════════╗
║                    MODEL EVALUATION SUMMARY                   ║
╠══════════════════════════════════════════════════════════════╣
║ Dataset Size: {len(data):,} URLs                              
║ Training Set: {len(X_train):,} | Test Set: {len(X_test):,}
║ Features: {X_train_features.shape[1]:,} (TF-IDF + Handcrafted)
╠══════════════════════════════════════════════════════════════╣
║ PERFORMANCE METRICS                                          ║
╠══════════════════════════════════════════════════════════════╣
║ Accuracy:        {accuracy_score(y_test, y_pred):.4f} ({accuracy_score(y_test, y_pred) * 100:.2f}%)
║ AUC-ROC:         {roc_auc_score(y_test, y_pred_prob):.4f}
║ F1-Score:        {f1_score(y_test, y_pred):.4f}
║ Precision:       {precision_score(y_test, y_pred):.4f}
║ Recall:          {recall_score(y_test, y_pred):.4f}
║ Avg Precision:   {avg_precision:.4f}
╠══════════════════════════════════════════════════════════════╣
║ CONFUSION MATRIX                                             ║
╠══════════════════════════════════════════════════════════════╣
║ True Negatives:  {cm[0, 0]:,} (Benign correctly identified)
║ False Positives: {cm[0, 1]:,} (False alarms - {cm[0, 1] / len(y_test) * 100:.2f}%)
║ False Negatives: {cm[1, 0]:,} (Missed threats - {cm[1, 0] / len(y_test) * 100:.2f}%) ⚠️
║ True Positives:  {cm[1, 1]:,} (Threats detected)
╠══════════════════════════════════════════════════════════════╣
║ BEST THRESHOLD: {best_threshold}                             
║ CV Mean AUC: {cv_scores.mean():.4f} (±{cv_scores.std():.4f})
╚══════════════════════════════════════════════════════════════╝
"""

print(report)

# Lưu báo cáo
with open('evaluation_report.txt', 'w', encoding='utf-8') as f:
    f.write(report)
print("\n✅ Đã lưu: evaluation_report.txt")

# 11. Model Comparison
print("\n" + "=" * 70)
print("📊 SO SÁNH VỚI BASELINE")
print("=" * 70)

comparison_data = {
    'Model': ['Random Baseline', 'LightGBM (Ours)'],
    'Accuracy': [0.5, accuracy_score(y_test, y_pred)],
    'AUC': [0.5, roc_auc_score(y_test, y_pred_prob)],
    'F1': [0.0, f1_score(y_test, y_pred)],
    'Recall': [0.5, recall_score(y_test, y_pred)],
    'Precision': [0.5, precision_score(y_test, y_pred)]
}

comparison_df = pd.DataFrame(comparison_data)
print("\n", comparison_df.to_string(index=False))

# ==================== SAVE MODEL ====================

print("\n" + "=" * 70)
print("💾 LƯU MÔ HÌNH")
print("=" * 70)

joblib.dump(model, "train_model.pkl")
joblib.dump(vectorizer, "tfidf_vectorizer.pkl")
joblib.dump({
    'threshold': best_threshold,
    'feature_names': feature_names,
    'auc': roc_auc_score(y_test, y_pred_prob),
    'f1': f1_score(y_test, y_pred),
    'recall': recall_score(y_test, y_pred),
    'accuracy': accuracy_score(y_test, y_pred),
    'precision': precision_score(y_test, y_pred),
    'avg_precision': avg_precision,
    'cv_mean': cv_scores.mean(),
    'cv_std': cv_scores.std()
}, "model_metadata.pkl")

print("✅ Đã lưu:")
print("   → train_model.pkl (LightGBM model)")
print("   → tfidf_vectorizer.pkl (TF-IDF vectorizer)")
print("   → model_metadata.pkl (Metadata & threshold)")

# ==================== TEST SAMPLES ====================

print("\n" + "=" * 70)
print("🧪 TEST VỚI MẪU THỰC TẾ")
print("=" * 70)

test_urls = [
    "https://www.google.com",
    "http://secure-paypal-verify-account.tk/login.php",
    "https://192.168.1.1/admin/login",
    "https://amaz0n-security-alert.com/update-payment",
    "https://github.com/user/repo",
    "http://www.facebok-security.ml/verify.php?id=12345",
]

for url in test_urls:
    features, _, _ = create_feature_matrix(pd.Series([url]), vectorizer=vectorizer)
    prob = model.predict(features, num_iteration=model.best_iteration)[0]
    pred = "🔴 MALICIOUS" if prob > best_threshold else "🟢 BENIGN"
    print(f"\n{pred} ({prob:.2%})")
    print(f"   {url}")

# ==================== VISUALIZATION SUMMARY ====================

print("\n" + "=" * 70)
print("📊 CÁC FILE VISUALIZATION ĐÃ TẠO")
print("=" * 70)
print("   ✅ roc_curve.png - ROC Curve")
print("   ✅ precision_recall_curve.png - Precision-Recall Curve")
print("   ✅ confusion_matrix.png - Confusion Matrix Heatmap")
print("   ✅ learning_curve.png - Learning Curve")
print("   ✅ evaluation_report.txt - Báo cáo tổng kết")

# ==================== FINAL SUMMARY ====================

print("\n" + "=" * 70)
print("✅ HOÀN TẤT!")
print("=" * 70)

print(f"""
🎉 Mô hình đã được huấn luyện và đánh giá thành công!

📈 Kết quả chính:
   • Accuracy:  {accuracy_score(y_test, y_pred):.2%}
   • AUC-ROC:   {roc_auc_score(y_test, y_pred_prob):.4f}
   • F1-Score:  {f1_score(y_test, y_pred):.4f}
   • Recall:    {recall_score(y_test, y_pred):.2%} (Detection Rate)

💾 Files đã lưu:
   • train_model.pkl
   • tfidf_vectorizer.pkl
   • model_metadata.pkl
   • roc_curve.png
   • precision_recall_curve.png
   • confusion_matrix.png
   • learning_curve.png
   • evaluation_report.txt

🚀 Sử dụng mô hình:
   model = joblib.load('train_model.pkl')
   vectorizer = joblib.load('tfidf_vectorizer.pkl')
   metadata = joblib.load('model_metadata.pkl')
""")

print("=" * 70)