#!/usr/bin/env python3

import uuid
import random
import datetime
import argparse
from faker import Faker
from pymongo import MongoClient

fake = Faker()

MONGO_URI = "mongodb://localhost:27017"
DB_NAME = "hive"

DEVICE_TYPES = ["android", "windows", "linux"]

SHARED_DOMAINS = [
    "evil-payments.com",
    "darkmail.net",
    "safe-chat.org",
    "crypto-transfer.io",
]

SHARED_EMAILS = [
    "admin@darkcorp.com",
    "ops@darkcorp.com",
    "control@darkcorp.com"
]

SHARED_SSIDS = [
    "SAFEHOUSE_WIFI",
    "OP_CENTER",
    "MOBILE_HUB"
]

LEAD_TYPES = [
    "Suspicious crypto wallet activity",
    "Shared infrastructure detected",
    "Cross-device entity correlation",
    "Possible phishing cluster",
]

def utcnow():
    return datetime.datetime.utcnow().isoformat()

def random_strength(score):
    if score >= .85:
        return "DEFINITIVE"
    elif score >= .65:
        return "STRONG"
    elif score >= .40:
        return "MODERATE"
    return "WEAK"

parser = argparse.ArgumentParser()
parser.add_argument("--devices", type=int, default=100)
parser.add_argument("--case-id", default="DEMO-001")
args = parser.parse_args()

client = MongoClient(MONGO_URI)
db = client[DB_NAME]

collections = [
    "devices",
    "entity_network",
    "device_relationships",
    "device_clusters",
    "timeline_correlations",
    "investigative_leads",
    "infrastructure_graph",
]

for c in collections:
    db[c].delete_many({})

devices = []

cluster_count = max(3, args.devices // 10)

clusters = []

for i in range(cluster_count):

    cluster_id = f"CLUSTER-{i+1:03}"

    shared_domain = random.choice(SHARED_DOMAINS)
    shared_email = random.choice(SHARED_EMAILS)
    shared_ssid = random.choice(SHARED_SSIDS)

    clusters.append({
        "cluster_id": cluster_id,
        "domain": shared_domain,
        "email": shared_email,
        "ssid": shared_ssid,
        "members": []
    })

for i in range(args.devices):

    device_id = f"DEV-{i+1:04}"

    cluster = random.choice(clusters)
    cluster["members"].append(device_id)

    doc = {
        "device_id": device_id,
        "case_id": args.case_id,
        "device_type": random.choice(DEVICE_TYPES),
        "device_model": fake.word().upper(),
        "device_os": random.choice([
            "Android 14",
            "Windows 11",
            "Ubuntu 24.04"
        ]),
        "created_at": utcnow()
    }

    db.devices.insert_one(doc)

    devices.append(device_id)

    entities = [

        {
            "entity_type": "EMAIL",
            "entity_value": cluster["email"]
        },

        {
            "entity_type": "DOMAIN",
            "entity_value": cluster["domain"]
        },

        {
            "entity_type": "WIFI_SSID",
            "entity_value": cluster["ssid"]
        },

        {
            "entity_type": "PHONE",
            "entity_value": fake.phone_number()
        },

        {
            "entity_type": "USERNAME",
            "entity_value": fake.user_name()
        }

    ]

    for e in entities:

        db.entity_network.insert_one({

            "entity_type": e["entity_type"],
            "entity_value": e["entity_value"],
            "devices": [device_id],
            "first_seen": utcnow(),
            "last_seen": utcnow()

        })

for cluster in clusters:

    db.device_clusters.insert_one({

        "cluster_id": cluster["cluster_id"],
        "devices": cluster["members"],
        "device_count": len(cluster["members"]),
        "cluster_type": random.choice([
            "PHISHING",
            "BOTNET",
            "MONEY_MULE"
        ]),
        "cohesion_score": round(random.uniform(.5, .95), 2)

    })

    members = cluster["members"]

    for i in range(len(members)):

        for j in range(i + 1, len(members)):

            score = round(random.uniform(.4, .95), 2)

            db.device_relationships.insert_one({

                "device_a": members[i],
                "device_b": members[j],
                "confidence_score": score,
                "strength": random_strength(score),
                "shared_entities": [
                    cluster["email"],
                    cluster["domain"]
                ]

            })

for i in range(args.devices * 2):

    db.investigative_leads.insert_one({

        "lead_id": str(uuid.uuid4()),
        "priority": random.choice([
            "HIGH",
            "MEDIUM",
            "LOW"
        ]),
        "title": random.choice(LEAD_TYPES),
        "created_at": utcnow()

    })

for i in range(args.devices * 20):

    db.timeline_correlations.insert_one({

        "event_time": utcnow(),
        "device_id": random.choice(devices),
        "event_type": random.choice([
            "LOGIN",
            "SMS",
            "BROWSER_VISIT",
            "DOWNLOAD",
            "APP_INSTALL"
        ])

    })

print()
print("========== HIVE MOCK DATA GENERATED ==========")
print("Devices:", args.devices)
print("Clusters:", cluster_count)
print("Timeline events:", args.devices * 20)
print("Relationships:", db.device_relationships.count_documents({}))
print("Leads:", db.investigative_leads.count_documents({}))
print()
