from datetime import datetime
from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()

client = MongoClient(os.getenv("MONGO_URI"))
db = client[os.getenv("SECURITY_DB")]

logs = db["attack_logs"]


def log_attack(ip, attack_type, reason, method, path):
    logs.insert_one({
        "ip": ip,
        "attack_type": attack_type,
        "reason": reason,
        "method": method,
        "path": path,
        "timestamp": datetime.utcnow()
    })

    print(f"[LOGGED] {attack_type} from {ip}")