import os
import sqlite3
import pandas as pd
import numpy as np
import xgboost as xgb
import json
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import error_logger

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'aegisx.db')
MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'xgb_model.joblib')
META_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'model_meta.json')

def calculate_stage1_score(amount: float, category: str) -> float:
    """Stage 1: Primary Risk Engine (recall-focused transaction-only risk score)."""
    score = 0.0
    
    # Base risk by amount
    if amount > 1000:
        score += 65.0
    elif amount > 500:
        score += 45.0
    elif amount > 200:
        score += 30.0
    elif amount > 50:
        score += 15.0
    else:
        score += 5.0
        
    # Base risk by merchant category
    high_risk_cats = ['es_travel', 'es_leisure', 'es_sportsandtoys', 'es_wellnessandbeauty']
    med_risk_cats = ['es_hotelsandservices', 'es_home', 'es_health']
    
    cat_clean = str(category).strip().strip("'").strip('"')
    if cat_clean in high_risk_cats:
        score += 30.0
    elif cat_clean in med_risk_cats:
        score += 15.0
    else:
        score += 5.0
        
    return min(score, 100.0)

def train_model():
    """Queries fused dataset, preprocesses features, trains XGBoost model, and saves it."""
    try:
        print("Querying database to build training dataset...")
        with sqlite3.connect(DB_PATH) as conn:
            # Query correlating transactions with telemetry in a 30-min window
            query = """
            SELECT 
                t.id as tx_id,
                t.amount,
                t.category,
                t.ip_address as tx_ip,
                t.fraud_label as label,
                tel.flow_duration,
                tel.total_fwd_packets,
                tel.total_bwd_packets,
                tel.fwd_packet_len_max,
                tel.bwd_packet_len_max,
                tel.dest_port,
                tel.protocol,
                tel.raw_label as tel_label,
                p.pqc_compliant,
                p.data_classification
            FROM transactions t
            LEFT JOIN telemetry tel ON t.incident_id = tel.incident_id OR (
                t.customer_id = tel.customer_id 
                AND tel.timestamp BETWEEN datetime(t.timestamp, '-30 minutes') AND t.timestamp
            )
            LEFT JOIN pqc_inventory p ON tel.asset_id = p.asset_id
            """
            df = pd.read_csv(conn_to_csv_helper(conn, query))
        
        print(f"Dataset queried: {len(df)} rows.")

        # Preprocessing NaNs
        df['flow_duration'] = df['flow_duration'].fillna(0)
        df['total_fwd_packets'] = df['total_fwd_packets'].fillna(0)
        df['total_bwd_packets'] = df['total_bwd_packets'].fillna(0)
        df['fwd_packet_len_max'] = df['fwd_packet_len_max'].fillna(0)
        df['bwd_packet_len_max'] = df['bwd_packet_len_max'].fillna(0)
        df['dest_port'] = df['dest_port'].fillna(0)
        df['protocol'] = df['protocol'].fillna(-1)
        df['pqc_compliant'] = df['pqc_compliant'].fillna(-1) # -1 means no telemetry
        
        df['category'] = df['category'].fillna('NONE')
        df['tel_label'] = df['tel_label'].fillna('NONE')
        df['data_classification'] = df['data_classification'].fillna('NONE')

        # Feature Engineering: IP Mismatch (anomalous VPN space)
        # In generator.py, incidents write external IP "103.45.68.X", whereas normal is "192.168.1.X"
        df['ip_anomaly'] = df['tx_ip'].apply(lambda ip: 1 if str(ip).startswith('103.45.68') else 0)

        # Stage 1 Score: Primary recall-focused transaction risk
        df['stage1_score'] = df.apply(lambda r: calculate_stage1_score(r['amount'], r['category']), axis=1)

        # Categorical Encoders (using explicit mapping for demo predictability and simplicity)
        categories = sorted(df['category'].unique().tolist())
        category_map = {cat: idx for idx, cat in enumerate(categories)}
        
        tel_labels = sorted(df['tel_label'].unique().tolist())
        tel_label_map = {lbl: idx for idx, lbl in enumerate(tel_labels)}
        
        classifications = sorted(df['data_classification'].unique().tolist())
        class_map = {cls: idx for idx, cls in enumerate(classifications)}

        # Encode strings
        df['category_encoded'] = df['category'].map(category_map)
        df['tel_label_encoded'] = df['tel_label'].map(tel_label_map)
        df['class_encoded'] = df['data_classification'].map(class_map)

        # Feature Selection (Two-Stage Meta-Labeling: stage1_score acts as Primary input)
        feature_cols = [
            'amount', 'category_encoded', 'flow_duration', 
            'total_fwd_packets', 'total_bwd_packets', 'fwd_packet_len_max', 
            'bwd_packet_len_max', 'dest_port', 'protocol', 
            'tel_label_encoded', 'pqc_compliant', 'class_encoded', 'ip_anomaly',
            'stage1_score'
        ]

        X = df[feature_cols]
        y = df['label']

        print(f"Class distribution: Benign={sum(y==0)}, Threat={sum(y==1)}")

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

        # Train XGBoost model
        print("Training XGBoost Meta-Model...")
        model = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=5,
            learning_rate=0.1,
            random_state=42,
            use_label_encoder=False,
            eval_metric='logloss'
        )
        model.fit(X_train, y_train)

        # Validate
        preds = model.predict(X_test)
        print("\n--- CLASSIFICATION REPORT ---")
        print(classification_report(y_test, preds))

        cm = confusion_matrix(y_test, preds)
        print("\n--- CONFUSION MATRIX ---")
        print(cm)

        # Save Model using joblib
        joblib.dump(model, MODEL_PATH)
        print(f"XGBoost model saved to {MODEL_PATH}")

        # Save Metadata (encoders & column list)
        meta = {
            "features": feature_cols,
            "category_map": category_map,
            "tel_label_map": tel_label_map,
            "class_map": class_map
        }
        with open(META_PATH, 'w') as f:
            json.dump(meta, f, indent=4)
        print(f"Model metadata saved to {META_PATH}")

    except Exception as e:
        error_logger.log_error("model_trainer.py:train_model", "Failed to train XGBoost model", e)
        raise

def conn_to_csv_helper(conn, query):
    """Executes SQLite query and returns a pandas-compatible buffer."""
    import io
    cursor = conn.cursor()
    cursor.execute(query)
    columns = [col[0] for col in cursor.description]
    data = cursor.fetchall()
    
    # Write to memory buffer
    df_temp = pd.DataFrame(data, columns=columns)
    buffer = io.StringIO()
    df_temp.to_csv(buffer, index=False)
    buffer.seek(0)
    return buffer

if __name__ == "__main__":
    train_model()
