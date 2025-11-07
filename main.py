from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from googleapiclient import discovery
from google.oauth2 import service_account
import json
import bcrypt
import jwt
import os
from datetime import datetime, timedelta

# -----------------------------
# ⚙️ Configuration
# -----------------------------
SECRET_KEY = "supersecretjwtkey"  # 🔒 Replace with a strong secret (use Secret Manager ideally)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

app = FastAPI(title="GCP Audit Agent", version="2.0")

# -----------------------------
# 🌐 Enable CORS
# -----------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ✅ Allow all origins (you can restrict later)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# ✅ Health Check
# -----------------------------
@app.get("/health")
def health_check():
    return {"status": "ok"}


# -----------------------------
# 🔐 Generate JWT Token
# -----------------------------
class AuthPayload(BaseModel):
    username: str
    password: str


@app.post("/login")
def login(payload: AuthPayload):
    # Example: password hashing and checking
    hashed_pw = bcrypt.hashpw(payload.password.encode('utf-8'), bcrypt.gensalt())

    # Normally, you'd check credentials from DB; here we mock success
    if payload.username != "admin":
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # ✅ Create JWT token
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = jwt.encode({"sub": payload.username, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}


# -----------------------------
# 🔍 Verify JWT Token
# -----------------------------
def verify_token(token: str):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return decoded
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# -----------------------------
# 🧠 Compute Engine Audit
# -----------------------------
def check_compute_public_ips(service_account_info: dict):
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


# -----------------------------
# 🚀 Main API - Upload JSON & Audit
# -----------------------------
@app.post("/audit-vms")
async def audit_vms(file: UploadFile = File(...), token: str = ""):
    """
    Takes a Service Account JSON file and audits Compute Engine instances for public IPs.
    """
    # 🔒 Verify JWT token before proceeding
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")
    verify_token(token)

    try:
        content = await file.read()
        sa_info = json.loads(content)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Uploaded file is not valid JSON.")

    # ✅ Audit public IPs
    return check_compute_public_ips(sa_info)
