from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from googleapiclient import discovery
from google.oauth2 import service_account

app = FastAPI(title="GCP Audit Agent", version="1.0")

# ---------------------------
# 📘 Request Model
# ---------------------------
class ServiceAccountPayload(BaseModel):
    service_account: dict  # Full JSON of the SA key


# ---------------------------
# 🔍 Audit Function
# ---------------------------
def check_compute_public_ips(service_account_info: dict):
    """
    Fetch public IPs of all VMs in the project
    associated with the given service account JSON.
    """
    try:
        # Create credentials from in-memory SA JSON
        creds = service_account.Credentials.from_service_account_info(service_account_info)
        project_id = creds.project_id
        if not project_id:
            raise HTTPException(status_code=400, detail="No project_id found in service account JSON.")

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

        return {"project_id": project_id, "vms": vm_data}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit error: {str(e)}")


# ---------------------------
# 🚀 API Endpoint
# ---------------------------
@app.post("/audit-vms")
def audit_vms(payload: ServiceAccountPayload):
    """
    Takes a service account JSON and returns all VM instances
    with public IPs from that project.
    """
    return check_compute_public_ips(payload.service_account)
