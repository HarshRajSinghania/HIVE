#!/usr/bin/env python3
"""
Wrapper to run HIVE Command Center with mongomock when MongoDB is not available.
"""
import mongomock
import sys
import pymongo

# Patch pymongo's MongoClient to use mongomock
pymongo.MongoClient = mongomock.MongoClient

# Now import the app and run it
from app import app

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="HIVE Command Center (with mongomock fallback)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true", default=True)
    args = parser.parse_args()
    
    print(f"  HIVE Command Center  v1.0.0 (using mongomock)")
    print(f"  MongoDB : mocked (in-memory)")
    print(f"  URL     : http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)