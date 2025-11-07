from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from googleapiclient import discovery
from google.oauth2 import service_account
from google.cloud import secretmanager
import json

from fastapi import UploadFile, File
from google.cloud import secretmanager
import json
import uuid

# ---------------------------------
# 🚀 Upload API — Securely Save SA JSON
# ---------------------------------
@app.post("/upload-sa")
async def upload_service_account(file: UploadFile = File(...)):
    """
    Accepts a service account JSON file, uploads it securely
    to Google Secret Manager, and returns the secret name.
    """
    try:
        # Read uploaded file content
        content = await file.read()
        sa_data = json.loads(content)

        # Validate basic structure
        if "client_email" not in sa_data or "private_key" not in sa_data:
            raise HTTPException(status_code=400, detail="Invalid service account JSON.")

        # Create a unique secret name (to avoid collisions)
        sa_email = sa_data["client_email"].split("@")[0]
        secret_id = f"{sa_email}-{uuid.uuid4().hex[:8]}"

        # The project where your app stores secrets
        audit_agent_project = "YOUR_AUDIT_APP_PROJECT_ID"

        client = secretmanager.SecretManagerServiceClient()
        parent = f"projects/{audit_agent_project}"

        # 1️⃣ Create the secret
        secret = client.create_secret(
            request={
                "parent": parent,
                "secret_id": secret_id,
                "secret": {"replication": {"automatic": {}}},
            }
        )

        # 2️⃣ Add the first version (the actual SA JSON)
        client.add_secret_version(
            request={
                "parent": secret.name,
                "payload": {"data": content},
            }
        )

        return {
            "message": "Service account securely uploaded.",
            "secret_name": f"{secret.name}/versions/latest"
        }

    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Uploaded file is not valid JSON.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


app = FastAPI(title="GCP Audit Agent", version="1.1")


# ---------------------------
# 📘 Request Model
# ---------------------------
class SecretRefPayload(BaseModel):
    secret_name: str  # e.g. "projects/my-project/secrets/audit-sa-001/versions/latest"


# ---------------------------
# 🧩 Helper — Load SA from Secret Manager
# ---------------------------
def load_service_account_from_secret(secret_name: str) -> dict:
    """
    Loads service account JSON stored in Google Secret Manager.
    """
    try:
        client = secretmanager.SecretManagerServiceClient()
        response = client.access_secret_version(request={"name": secret_name})
        payload = response.payload.data.decode("utf-8")
        return json.loads(payload)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load secret: {str(e)}")


# ---------------------------
# 🔍 Audit Function
# ---------------------------
def check_compute_public_ips(service_account_info: dict):
    """
    Fetch public IPs of all VMs in the project
    associated with the given service account JSON.
    """
    try:
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
def audit_vms(payload: SecretRefPayload):
    """
    Takes a Secret Manager reference and returns all VM instances
    with public IPs from that project.
    """
    service_account_info = load_service_account_from_secret(payload.secret_name)
    return check_compute_public_ips(service_account_info)
