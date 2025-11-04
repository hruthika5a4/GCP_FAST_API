from fastapi import FastAPI
from audit_checks import (
    check_compute_public_ips,
    check_sql_public_ips
)

app = FastAPI()

@app.get("/")
def root():
    return {"status": "GCP Audit API Running ✅"}

@app.get("/public_ips")
def get_public_ips():
    return check_compute_public_ips()

@app.get("/sql_ips")
def get_sql_ips():
    return check_sql_public_ips()

@app.get("/private_gke")
def get_sql_ips():
    return check_gke_clusters()

@app.get("/sa_owner")
def get_sql_ips():
    return check_owner_service_accounts()

@app.get("/public_buckets")
def get_sql_ips():
    return check_public_buckets()
