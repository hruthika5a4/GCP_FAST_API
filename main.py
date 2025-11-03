from fastapi import FastAPI
import os
from audit_checks import check_compute_public_ips

app = FastAPI()

@app.get("/")
def root():
    return {"status": "Cloud Run FastAPI GCP Audit is running"}

@app.get("/public_ips")
def get_public_ips():
    project_id = os.environ.get("PROJECT_ID")
    if not project_id:
        return {"error": "PROJECT_ID env var not set"}

    data = check_compute_public_ips(project_id)
    return {"project": project_id, "public_ips": data}
