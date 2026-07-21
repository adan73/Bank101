from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()

client = MongoClient(os.getenv("MONGO_URI"))

security_db = client[os.getenv("SECURITY_DB")]

blacklist = security_db["blacklist"]


def is_blacklisted(ip):
    return blacklist.find_one({"ip": ip}) is not None


def add_to_blacklist(ip, reason):

    if is_blacklisted(ip):
        return

    blacklist.insert_one({
        "ip": ip,
        "reason": reason
    })

    print(f"[BLACKLIST] {ip} added ({reason})")


def remove_from_blacklist(ip):

    blacklist.delete_one({"ip": ip})

    print(f"[BLACKLIST] {ip} removed")


def get_all_blacklisted():

    return list(blacklist.find({}, {"_id": 0}))