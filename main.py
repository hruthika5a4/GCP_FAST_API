from fastapi import FastAPI, UploadFile, File, HTTPException
from googleapiclient import discovery
from google.oauth2 import service_account
import json

app = FastAPI(title="GCP VM Audit", version="1.0")

def check_compute_public_ips(service_account_info: dict):
    try:
        creds = service_account.Credentials.from_service_account_info(service_account_info)
        project_id = creds.project_id
        compute = discovery.build("compute", "v1", credentials=creds)
        vm_data = []

        req = compute.instances().aggregatedList(project=project_id)
        while req is not None:
            res = req.execute()
            for zone, scoped_list in res.get("items", {}).items():
                for instance in scoped_list.get("instances", []):
                    name = instance["name"]
                    for nic in instance.get("networkInterfaces", []):
                        for ac in nic.get("accessConfigs", []):
                            if "natIP" in ac:
                                vm_data.append({
                                    "vm_name": name,
                                    "zone": zone.split("/")[-1],
                                    "public_ip": ac["natIP"]
                                })
            req = compute.instances().aggregatedList_next(req, res)

        return {
            "project_id": project_id,
            "vulnerable_vms": vm_data or "✅ No public IPs found — all VMs are safe"
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit error: {str(e)}")

@app.post("/vm_audit")
async def vm_audit(file: UploadFile = File(...)):
    """
    Upload a GCP Service Account JSON file and audit for public VM IPs.
    """
    try:
        content = await file.read()
        sa_info = json.loads(content)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON file uploaded.")

    return check_compute_public_ips(sa_info)
