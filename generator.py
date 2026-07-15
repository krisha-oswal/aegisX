import os
import zipfile
import sqlite3
import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta
import json
import error_logger

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'aegisx.db')
SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'schema.sql')
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')

def init_db():
    """Initializes the database using schema.sql."""
    try:
        conn = sqlite3.connect(DB_PATH)
        with open(SCHEMA_PATH, 'r') as f:
            schema_sql = f.read()
        conn.executescript(schema_sql)
        conn.commit()
        conn.close()
        print("Database initialized successfully.")
    except Exception as e:
        error_logger.log_error("generator.py:init_db", "Failed to initialize database", e)
        raise

def clean_value(val):
    """Strips quotes from values if they are strings."""
    if isinstance(val, str):
        return val.strip().strip("'").strip('"')
    return val

def load_datasets():
    """Extracts BankSim and loads raw dataframes for sampling."""
    try:
        # Load BankSim transactions
        zip_path = os.path.join(DATA_DIR, 'archive.zip')
        with zipfile.ZipFile(zip_path, 'r') as z:
            with z.open('bs140513_032310.csv') as f:
                df_banksim = pd.read_csv(f)
        
        # Clean quotes from string fields in BankSim
        for col in ['customer', 'age', 'gender', 'merchant', 'category']:
            df_banksim[col] = df_banksim[col].apply(clean_value)
        
        print(f"Loaded BankSim: {len(df_banksim)} rows.")

        # Load CICIDS2017 files (selecting critical columns and stripping headers)
        cicids_cols = [
            'Destination Port', 'Flow Duration', 'Total Fwd Packets', 
            'Total Backward Packets', 'Total Length of Fwd Packets', 
            'Total Length of Bwd Packets', 'Fwd Packet Length Max', 
            'Bwd Packet Length Max', 'Protocol', 'Label'
        ]
        
        # Tuesday: SSH/FTP Patator
        tue_path = os.path.join(DATA_DIR, 'Tuesday-WorkingHours.pcap_ISCX.csv')
        df_tue_preview = pd.read_csv(tue_path, nrows=5)
        tue_cols_stripped = {c: c.strip() for c in df_tue_preview.columns}
        df_tue = pd.read_csv(tue_path)
        df_tue.rename(columns=tue_cols_stripped, inplace=True)
        # Select target columns and attacks
        df_tue = df_tue[df_tue['Label'].isin(['SSH-Patator', 'FTP-Patator', 'BENIGN'])]
        print(f"Loaded Tuesday CICIDS: {len(df_tue)} rows.")

        # Thursday: Web Attacks
        thu_path = os.path.join(DATA_DIR, 'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv')
        df_thu_preview = pd.read_csv(thu_path, nrows=5)
        thu_cols_stripped = {c: c.strip() for c in df_thu_preview.columns}
        df_thu = pd.read_csv(thu_path)
        df_thu.rename(columns=thu_cols_stripped, inplace=True)
        df_thu = df_thu[df_thu['Label'].str.contains('Web Attack|BENIGN', na=False)]
        print(f"Loaded Thursday CICIDS: {len(df_thu)} rows.")

        # Friday: Port Scan
        fri_path = os.path.join(DATA_DIR, 'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv')
        df_fri_preview = pd.read_csv(fri_path, nrows=5)
        fri_cols_stripped = {c: c.strip() for c in df_fri_preview.columns}
        df_fri = pd.read_csv(fri_path)
        df_fri.rename(columns=fri_cols_stripped, inplace=True)
        df_fri = df_fri[df_fri['Label'].isin(['PortScan', 'BENIGN'])]
        print(f"Loaded Friday CICIDS: {len(df_fri)} rows.")

        return df_banksim, df_tue, df_thu, df_fri
    except Exception as e:
        error_logger.log_error("generator.py:load_datasets", "Failed to load datasets", e)
        raise

def generate_pqc_assets():
    """Generates a default set of PQC Assets."""
    assets = [
        {
            "asset_id": "AST-902",
            "asset_name": "Auth Endpoint (Legacy OAuth)",
            "algorithm": "RSA-2048",
            "pqc_compliant": 0,
            "data_classification": "HNDL"
        },
        {
            "asset_id": "AST-401",
            "asset_name": "Core Transaction Database",
            "algorithm": "ECC-256",
            "pqc_compliant": 0,
            "data_classification": "Confidential"
        },
        {
            "asset_id": "AST-101",
            "asset_name": "Cloud Edge Gateway",
            "algorithm": "Kyber-512",
            "pqc_compliant": 1,
            "data_classification": "Public"
        },
        {
            "asset_id": "AST-505",
            "asset_name": "Customer Profile Registry",
            "algorithm": "Kyber-1024",
            "pqc_compliant": 1,
            "data_classification": "Confidential"
        }
    ]
    return assets

def get_protocol(port):
    """Maps common ports to protocol integer (TCP=6, UDP=17)."""
    try:
        p = int(port)
        return 17 if p in [53, 123, 161, 162, 1900] else 6
    except:
        return 6

def build_data_pipeline():
    """Builds and populates the SQLite database with fused BankSim and CICIDS2017 data."""
    try:
        init_db()
        df_bs, df_tue, df_thu, df_fri = load_datasets()
        
        # 1. Identity Fabric
        print("Building identity fabric...")
        unique_customers = df_bs['customer'].unique()
        random.seed(42)
        np.random.seed(42)
        
        # Build customer mappings
        identity_fabric = {}
        for cust in unique_customers:
            home_ip = f"192.168.1.{random.randint(10, 254)}"
            dev_id = f"DEV-{random.randint(100000, 999999)}"
            identity_fabric[cust] = {
                "home_ip": home_ip,
                "device_id": dev_id,
                "risk_pool": False
            }
        
        # Designate ~12% for the risk pool
        risk_pool_size = int(len(unique_customers) * 0.12)
        risk_customers = random.sample(list(unique_customers), risk_pool_size)
        for rc in risk_customers:
            identity_fabric[rc]["risk_pool"] = True
        
        # Open database connection with context manager to ensure release
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            
            # 2. Write PQC Assets
            pqc_assets = generate_pqc_assets()
            for asset in pqc_assets:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO pqc_inventory (asset_id, asset_name, algorithm, pqc_compliant, data_classification)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (asset["asset_id"], asset["asset_name"], asset["algorithm"], asset["pqc_compliant"], asset["data_classification"])
                )
            print("PQC Assets written.")

            # Let's create an anchor time for the demo: 2026-07-14 09:00:00
            anchor_date = datetime(2026, 7, 14, 9, 0, 0)
            
            # Prepare lists for DB insertion
            tx_insert_rows = []
            tel_insert_rows = []
            
            # Filter raw datasets into threat-archetype rows and benign background rows
            attacks_tue = df_tue[df_tue['Label'] != 'BENIGN'].copy()
            attacks_thu = df_thu[df_thu['Label'] != 'BENIGN'].copy()
            attacks_fri = df_fri[df_fri['Label'] != 'BENIGN'].copy()

            benign_tue = df_tue[df_tue['Label'] == 'BENIGN'].sample(1000, random_state=42).copy()
            benign_thu = df_thu[df_thu['Label'] == 'BENIGN'].sample(1000, random_state=42).copy()
            benign_fri = df_fri[df_fri['Label'] == 'BENIGN'].sample(1000, random_state=42).copy()

            # Clean columns and index trackers
            for df in [attacks_tue, attacks_thu, attacks_fri, benign_tue, benign_thu, benign_fri]:
                df.columns = [c.strip() for c in df.columns]

            print("Generating transactions and telemetry tables...")
            # To make a balanced dataset for the demo and model trainer:
            # We will generate ~1,500 total transactions (containing ~200 fraud labels and attacks)
            # We will inject 150 incidents:
            # Archetype 1: Credential Theft (Tues SSH/FTP Patator) + high BankSim transaction
            # Archetype 2: App Compromise (Thurs Web Attack) + high BankSim transaction
            # Archetype 3: Recon-Only (Fri Port Scan) + no transaction (or delayed by days)
            
            # Let's pull some fraud and non-fraud rows from BankSim
            bs_fraud = df_bs[df_bs['fraud'] == 1].sample(150, random_state=42).copy()
            bs_benign = df_bs[df_bs['fraud'] == 0].sample(1350, random_state=42).copy()
            
            # Combine and assign fake timestamps
            all_bs = pd.concat([bs_fraud, bs_benign]).sample(frac=1.0, random_state=42).reset_index(drop=True)
            
            incident_counter = 1
            
            # Iterate over transaction records
            for idx, row in all_bs.iterrows():
                cust = row['customer']
                fabric = identity_fabric[cust]
                tx_id = f"TX-{100000 + idx}"
                
                # Map default fields
                step_min = int(row['step']) * 15 # 1 step = 15 mins roughly
                tx_time = anchor_date + timedelta(minutes=step_min) + timedelta(seconds=random.randint(0, 59))
                
                incident_id = None
                is_fraud = int(row['fraud'])
                
                # Check if this customer is in risk pool AND transaction is fraud -> Let's link an attack incident!
                if fabric['risk_pool'] and is_fraud == 1 and incident_counter <= 100:
                    incident_id = f"INC-{1000 + incident_counter}"
                    # Choose archetype: Credential Theft or App Compromise
                    arch = random.choice(['cred_theft', 'app_compromise'])
                    
                    # Sample a matching attack flow
                    if arch == 'cred_theft':
                        flow_row = attacks_tue.sample(1).iloc[0]
                        asset_id = "AST-902" # Legacy Auth Endpoint
                    else:
                        flow_row = attacks_thu.sample(1).iloc[0]
                        asset_id = "AST-401" # Core DB
                        
                    flow_duration = int(flow_row['Flow Duration'])
                    # compute timestamps
                    attack_end = tx_time - timedelta(minutes=random.randint(2, 10))
                    attack_start = attack_end - timedelta(microseconds=flow_duration)
                    
                    # Generate a unique ID for the telemetry event
                    tel_id = f"TEL-{200000 + incident_counter}"
                    dest_port = int(flow_row['Destination Port'])
                    
                    # Append telemetry record
                    tel_insert_rows.append((
                        tel_id,
                        attack_start.strftime('%Y-%m-%d %H:%M:%S'),
                        cust,
                        fabric['home_ip'],
                        "10.0.0.5", # Destination Server IP
                        dest_port,
                        flow_duration,
                        int(flow_row['Total Fwd Packets']),
                        int(flow_row['Total Backward Packets']),
                        float(flow_row['Fwd Packet Length Max']),
                        float(flow_row['Bwd Packet Length Max']),
                        get_protocol(dest_port),
                        str(flow_row['Label']),
                        asset_id,
                        incident_id
                    ))
                    incident_counter += 1
                
                # Write transaction row
                tx_insert_rows.append((
                    tx_id,
                    int(row['step']),
                    cust,
                    str(row['age']),
                    str(row['gender']),
                    str(row['zipcodeOri']),
                    str(row['merchant']),
                    str(row['zipMerchant']),
                    str(row['category']),
                    float(row['amount']),
                    is_fraud,
                    fabric['device_id'],
                    fabric['home_ip'] if not incident_id else f"103.45.68.{random.randint(10, 254)}", # Anomalous IP if incident!
                    incident_id,
                    tx_time.strftime('%Y-%m-%d %H:%M:%S')
                ))
                
            # 3. Add Telemetry-First (Recon-Only / Port Scan) Incidents
            # These are security anomalies with no initial fraudulent transactions.
            print("Injecting Port Scan telemetry-first incidents...")
            port_scan_customers = random.sample([c for c, f in identity_fabric.items() if f['risk_pool']], 30)
            for p_cust in port_scan_customers:
                incident_id = f"INC-{1000 + incident_counter}"
                flow_row = attacks_fri.sample(1).iloc[0]
                flow_duration = int(flow_row['Flow Duration'])
                dest_port = int(flow_row['Destination Port'])
                
                # Anchor at a random time
                attack_time = anchor_date + timedelta(minutes=random.randint(100, 1000))
                tel_id = f"TEL-{200000 + incident_counter}"
                
                # Telemetry record (Port Scan)
                tel_insert_rows.append((
                    tel_id,
                    attack_time.strftime('%Y-%m-%d %H:%M:%S'),
                    p_cust,
                    identity_fabric[p_cust]['home_ip'],
                    "10.0.0.22",
                    dest_port,
                    flow_duration,
                    int(flow_row['Total Fwd Packets']),
                    int(flow_row['Total Backward Packets']),
                    float(flow_row['Fwd Packet Length Max']),
                    float(flow_row['Bwd Packet Length Max']),
                    get_protocol(dest_port),
                    str(flow_row['Label']),
                    "AST-101", # Cloud Edge Gateway
                    incident_id
                ))
                incident_counter += 1
                
            # 4. Insert Background Benign Telemetry noise (CICIDS Benign rows)
            print("Adding background telemetry noise...")
            all_benign_flows = pd.concat([benign_tue, benign_thu, benign_fri]).sample(500, random_state=42)
            benign_counter = 0
            for idx, flow_row in all_benign_flows.iterrows():
                cust = random.choice(unique_customers)
                fabric = identity_fabric[cust]
                flow_duration = int(flow_row['Flow Duration'])
                dest_port = int(flow_row['Destination Port'])
                tel_time = anchor_date + timedelta(minutes=random.randint(0, 1500))
                tel_id = f"TEL-BG-{benign_counter}"
                
                # Write benign flow
                tel_insert_rows.append((
                    tel_id,
                    tel_time.strftime('%Y-%m-%d %H:%M:%S'),
                    cust,
                    fabric['home_ip'],
                    "10.0.2.15",
                    dest_port,
                    flow_duration,
                    int(flow_row['Total Fwd Packets']),
                    int(flow_row['Total Backward Packets']),
                    float(flow_row['Fwd Packet Length Max']),
                    float(flow_row['Bwd Packet Length Max']),
                    get_protocol(dest_port),
                    str(flow_row['Label']),
                    random.choice(["AST-101", "AST-505"]),
                    None
                ))
                benign_counter += 1

            # Commit insert statements to SQLite
            print(f"Writing {len(tx_insert_rows)} Transactions to DB...")
            cursor.executemany(
                """
                INSERT OR REPLACE INTO transactions 
                (id, step, customer_id, age, gender, zipcode_ori, merchant, zip_merchant, category, amount, fraud_label, device_id, ip_address, incident_id, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                tx_insert_rows
            )
            
            print(f"Writing {len(tel_insert_rows)} Telemetry records to DB...")
            cursor.executemany(
                """
                INSERT OR REPLACE INTO telemetry 
                (id, timestamp, customer_id, source_ip, dest_ip, dest_port, flow_duration, total_fwd_packets, total_bwd_packets, fwd_packet_len_max, bwd_packet_len_max, protocol, raw_label, asset_id, incident_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                tel_insert_rows
            )
            
        print("Data generation complete. Database successfully populated with fused BankSim and CICIDS2017 logs.")
        
        # 5. Pre-populate alerts for the demo
        print("Pre-populating demo alerts queue...")
        from orchestrator import SecurityOrchestrator
        orch = SecurityOrchestrator()
        
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            # Fetch some transactions with incident_id
            cursor.execute("SELECT customer_id, timestamp FROM transactions WHERE incident_id IS NOT NULL LIMIT 12")
            tx_incidents = cursor.fetchall()
            
        for cust_id, ts in tx_incidents:
            orch.evaluate_incident(cust_id, ts, trigger_type="transaction")
            
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            # Fetch some telemetry-first PortScan incidents
            cursor.execute("SELECT customer_id, timestamp FROM telemetry WHERE raw_label = 'PortScan' LIMIT 3")
            tel_incidents = cursor.fetchall()
            
        for cust_id, ts in tel_incidents:
            orch.evaluate_incident(cust_id, ts, trigger_type="telemetry")
            
        # 6. Pre-populate analyst feedback
        print("Pre-populating analyst feedback logs...")
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            
            # True Threats (high scores)
            cursor.execute("SELECT id FROM alerts WHERE composite_score > 70 LIMIT 2")
            high_alerts = cursor.fetchall()
            for a_id in high_alerts:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO feedback (alert_id, status, analyst_notes, timestamp) 
                    VALUES (?, 'True Threat', 'Correlated SSH brute force and high transaction amount matches account takeover pattern.', datetime('now'))
                    """,
                    (a_id[0],)
                )
                
            # False Positives (low scores)
            cursor.execute("SELECT id FROM alerts WHERE composite_score < 30 LIMIT 2")
            low_alerts = cursor.fetchall()
            for a_id in low_alerts:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO feedback (alert_id, status, analyst_notes, timestamp) 
                    VALUES (?, 'False Positive', 'Standard transaction, no anomalous telemetry detected.', datetime('now'))
                    """,
                    (a_id[0],)
                )
            conn.commit()
            
        print("Demo database pre-population complete.")
        
    except Exception as e:
        error_logger.log_error("generator.py:build_data_pipeline", "Failed to build data pipeline", e)
        raise

if __name__ == "__main__":
    build_data_pipeline()
