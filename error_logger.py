import sqlite3
import traceback
import os
import logging
from datetime import datetime

# Define database and log file paths
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'aegisx.db')
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'error.log')

# Setup basic file logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.ERROR,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('AegisXLogger')

def log_error(module_name: str, error_message: str, exception: Exception = None):
    """
    Logs an error to both error.log and the SQLite database.
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    stack_trace = None
    if exception:
        stack_trace = "".join(traceback.format_exception(type(exception), exception, exception.__traceback__))
    
    # Log to file
    log_msg = f"[{module_name}] {error_message}"
    if stack_trace:
        log_msg += f"\nStack Trace:\n{stack_trace}"
    logger.error(log_msg)
    
    # Log to SQLite
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO error_logs (timestamp, module, error_message, stack_trace)
            VALUES (?, ?, ?, ?)
            """,
            (timestamp, module_name, error_message, stack_trace)
        )
        conn.commit()
        conn.close()
    except Exception as db_err:
        # Fallback console print if DB logging fails
        print(f"FAILED TO LOG ERROR TO DATABASE: {db_err}")
        print(f"Original Error: {error_message}")

def get_error_logs(limit: int = 50):
    """
    Retrieves the latest error logs from the database.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, timestamp, module, error_message, stack_trace FROM error_logs ORDER BY id DESC LIMIT ?",
            (limit,)
        )
        logs = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return logs
    except Exception as e:
        print(f"Error fetching logs from database: {e}")
        return []
