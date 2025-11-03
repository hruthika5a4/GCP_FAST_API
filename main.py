from fastapi import FastAPI
from audit_checks import (
    check_compute_public_ips,
    check_sql_public_ips,
    check_gke_clusters,
    check_owner_service_accounts,
    check_public_buckets,
    check_load_balancers_audit,
    check_firewall_rules,
    check_cloud_functions_and_run
)

app = FastAPI(title="GCP Security Audit APIs")

@app.get("/")
def root():
    return {"message": "GCP Audit FastAPI Running 🚀"}

@app.get("/compute/public_ips")
def compute_public_ips():
    return {"data": check_compute_public_ips()}

@app.get("/sql/public_ips")
def sql_public_ips():
    return {"data": check_sql_public_ips()}

@app.get("/gke/public_clusters")
def gke_clusters():
    return {"data": check_gke_clusters()}

@app.get("/iam/owner_service_accounts")
def owner_service_accounts():
    return {"data": check_owner_service_accounts()}

@app.get("/storage/public_buckets")
def public_buckets():
    return {"data": check_public_buckets()}

@app.get("/loadbalancer/audit")
def load_balancers():
    return {"data": check_load_balancers_audit()}

@app.get("/firewall/public_rules")
def firewall_rules():
    return {"data": check_firewall_rules()}

@app.get("/serverless/functions_run_audit")
def functions_and_run():
    return {"data": check_cloud_functions_and_run()}
