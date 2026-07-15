-- Schema for AegisX Cybersecurity Telemetry & Transactional Behavior Correlation Engine

-- Transactions table (aligned with BankSim data schema)
CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY,
    step INTEGER,
    customer_id TEXT NOT NULL,
    age TEXT,
    gender TEXT,
    zipcode_ori TEXT,
    merchant TEXT,
    zip_merchant TEXT,
    category TEXT,
    amount REAL NOT NULL,
    fraud_label INTEGER DEFAULT 0, -- 0 = Normal, 1 = Fraud
    device_id TEXT,
    ip_address TEXT,
    incident_id TEXT,
    timestamp DATETIME -- Anchor timestamp
);

-- Cybersecurity Telemetry table (aligned with CICIDS2017 data schema)
CREATE TABLE IF NOT EXISTS telemetry (
    id TEXT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    customer_id TEXT NOT NULL,
    source_ip TEXT,
    dest_ip TEXT,
    dest_port INTEGER,
    flow_duration INTEGER,
    total_fwd_packets INTEGER,
    total_bwd_packets INTEGER,
    fwd_packet_len_max REAL,
    bwd_packet_len_max REAL,
    protocol INTEGER,
    raw_label TEXT, -- BENIGN, PortScan, SSH-Patator, Web Attack, etc.
    asset_id TEXT,
    incident_id TEXT
);

-- Post-Quantum Cryptography Asset Inventory table
CREATE TABLE IF NOT EXISTS pqc_inventory (
    asset_id TEXT PRIMARY KEY,
    asset_name TEXT NOT NULL,
    algorithm TEXT NOT NULL, -- RSA-2048, ECC-256, Kyber-512
    pqc_compliant INTEGER DEFAULT 0, -- 0 = No, 1 = Yes
    data_classification TEXT NOT NULL -- HNDL, Confidential, Public
);

-- Correlated Alerts table
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    trigger_type TEXT NOT NULL, -- transaction, telemetry
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    customer_id TEXT NOT NULL,
    composite_score REAL DEFAULT 0.0,
    status TEXT DEFAULT 'New', -- New, Investigating, Resolved
    xgb_score REAL DEFAULT 0.0,
    pqc_bump REAL DEFAULT 0.0,
    shap_values_json TEXT, -- JSON representation of SHAP features and values
    llm_summary TEXT,
    details_json TEXT -- JSON containing matched transactions/telemetry/PQC info
);

-- Analyst Feedback table
CREATE TABLE IF NOT EXISTS feedback (
    alert_id TEXT PRIMARY KEY,
    status TEXT NOT NULL, -- True Threat, False Positive
    analyst_notes TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(alert_id) REFERENCES alerts(id)
);

-- System Error Logs table
CREATE TABLE IF NOT EXISTS error_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    module TEXT NOT NULL,
    error_message TEXT NOT NULL,
    stack_trace TEXT
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_transactions_customer ON transactions(customer_id);
CREATE INDEX IF NOT EXISTS idx_transactions_incident ON transactions(incident_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_customer ON telemetry(customer_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_incident ON telemetry(incident_id);
CREATE INDEX IF NOT EXISTS idx_alerts_customer ON alerts(customer_id);
CREATE INDEX IF NOT EXISTS idx_alerts_score ON alerts(composite_score);
