from fastapi import FastAPI
from audit_checks import (
    check_compute_public_ips,
    check_sql_public_ips,
    check_public_buckets,
    check_owner_service_accounts,
    check_gke_clusters
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

@app.get("/gke_public_endpoints")
def get_gke_endpoints():
    return check_gke_clusters()

@app.get("/owner_sa")
def get_owner_sa():
    return check_owner_service_accounts()

@app.get("/public_buckets")
def get_public_buckets_route():
    return check_public_buckets()
