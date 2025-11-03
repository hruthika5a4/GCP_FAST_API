from fastapi import FastAPI, Query
from google.auth import default
from audit_checks import (
    check_compute_public_ips,
    check_sql_public_ips,
    check_gke_clusters,
    check_owner_service_accounts,
    check_public_buckets,
    check_firewall_rules,
    check_load_balancers_audit,
    check_cloud_functions_and_run
)

app = FastAPI(title="GCP Security Audit API")


# Root endpoint
@app.get("/")
def root():
    return {"message": "GCP Audit API is running ✅"}


# Compute Audit
@app.get("/audit/compute")
def audit_compute(project: str = Query(...)):
    creds, _ = default()
    return check_compute_public_ips(creds, project)


# SQL Audit
@app.get("/audit/sql")
def audit_sql(project: str = Query(...)):
    creds, _ = default()
    return check_sql_public_ips(creds, project)


# GKE Audit
@app.get("/audit/gke")
def audit_gke(project: str = Query(...)):
    creds, _ = default()
    return check_gke_clusters(creds, project)


# IAM Audit
@app.get("/audit/iam")
def audit_iam(project: str = Query(...)):
    creds, _ = default()
    return check_owner_service_accounts(creds, project)


# Bucket Audit
@app.get("/audit/buckets")
def audit_buckets(project: str = Query(...)):
    creds, _ = default()
    return check_public_buckets(creds, project)


# Firewall Audit
@app.get("/audit/firewall")
def audit_firewall(project: str = Query(...)):
    creds, _ = default()
    return check_firewall_rules(creds, project)


# Load Balancers Audit
@app.get("/audit/loadbalancers")
def audit_lb(project: str = Query(...)):
    creds, _ = default()
    return check_load_balancers_audit(creds, project)


# Cloud Run & Functions Audit
@app.get("/audit/cloud")
def audit_cloud(project: str = Query(...)):
    creds, _ = default()
    return check_cloud_functions_and_run(creds, project)


# Combined Audit
@app.get("/audit/all")
def audit_all(project: str = Query(...)):
    creds, _ = default()

    return {
        "compute": check_compute_public_ips(creds, project),
        "sql": check_sql_public_ips(creds, project),
        "gke": check_gke_clusters(creds, project),
        "iam": check_owner_service_accounts(creds, project),
        "buckets": check_public_buckets(creds, project),
        "firewall": check_firewall_rules(creds, project),
        "load_balancers": check_load_balancers_audit(creds, project),
        "cloud_services": check_cloud_functions_and_run(creds, project),
    }
