from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse, FileResponse
from datetime import datetime
from google.auth import default

from app.audit_checks import *
from app.report_excel import create_excel_report
from app.report_email import send_audit_email

app = FastAPI(title="GCP Security Audit API")

def get_creds(project):
    credentials, detected_project = default()
    if detected_project != project:
        raise Exception("GCP project credentials mismatch")
    return credentials

@app.get("/")
def home():
    return {"message": "✅ FastAPI GCP Security Audit Running"}

# ------------ Individual APIs ------------

@app.get("/audit/compute")
def compute(project: str):
    creds = get_creds(project)
    return check_compute_public_ips(creds, project)

@app.get("/audit/sql")
def sql(project: str):
    creds = get_creds(project)
    return check_sql_public_ips(creds, project)

@app.get("/audit/gke")
def gke(project: str):
    creds = get_creds(project)
    return check_gke_clusters(creds, project)

@app.get("/audit/service-accounts")
def service_accounts(project: str):
    creds = get_creds(project)
    return check_owner_service_accounts(creds, project)

@app.get("/audit/buckets")
def buckets(project: str):
    creds = get_creds(project)
    return check_public_buckets(creds, project)

@app.get("/audit/firewall")
def firewall(project: str):
    creds = get_creds(project)
    return check_firewall_rules(creds, project)

@app.get("/audit/load-balancers")
def lb(project: str):
    creds = get_creds(project)
    return check_load_balancers_audit(creds, project)

@app.get("/audit/cloud-services")
def cloud_services(project: str):
    creds = get_creds(project)
    return check_cloud_functions_and_run(creds, project)

# ------------ Full report API ------------

@app.get("/audit/all")
def full_audit(project: str, email: str):
    creds = get_creds(project)

    data = {
        "compute": check_compute_public_ips(creds, project),
        "sql": check_sql_public_ips(creds, project),
        "gke": check_gke_clusters(creds, project),
        "service_accounts": check_owner_service_accounts(creds, project),
        "buckets": check_public_buckets(creds, project),
        "firewall": check_firewall_rules(creds, project),
        "load_balancers": check_load_balancers_audit(creds, project),
        "cloud_services": check_cloud_functions_and_run(creds, project),
    }

    file_name = f"GCP_Audit_{project}_{datetime.now().strftime('%Y%m%d%H%M')}.xlsx"
    excel_path = create_excel_report(data, file_name)

    send_audit_email(project, excel_path, email)

    return FileResponse(
        excel_path,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        filename=file_name
    )
