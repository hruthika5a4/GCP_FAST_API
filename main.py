from fastapi import FastAPI, UploadFile, File, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from googleapiclient import discovery
from google.oauth2 import service_account
from datetime import datetime, timedelta
import json
import bcrypt
import jwt
import os

# -----------------------------
# ⚙️ Configuration
# -----------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretjwtkey")  # Use Secret Manager in prod
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

app = FastAPI(title="GCP VM Audit API", version="2.0")

# -----------------------------
# 🌐 Enable CORS
# -----------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ✅ Allow all (restrict in production)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# 🔐 Authentication Models
# -----------------------------
class LoginPayload(BaseModel):
    username: str
    password: str

# Mock user credentials (for demo)
USER_DB = {
    "admin": bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
}

# -----------------------------
# 🔐 Login & JWT Tokenization
# -----------------------------
@app.post("/login")
def login(payload: LoginPayload):
    username = payload.username
    password = payload.password.encode('utf-8')

    if username not in USER_DB:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    stored_hash = USER_DB[username].encode('utf-8')
    if not bcrypt.checkpw(password, stored_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # ✅ Create JWT token
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = jwt.encode({"sub": username, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}


# -----------------------------
# 🔍 Verify JWT Token
# -----------------------------
def verify_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# -----------------------------
# 🧠 VM Audit Function
# -----------------------------
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


# -----------------------------
# 🚀 VM Audit Endpoint (JSON File Upload)
# -----------------------------
@app.post("/vm_audit")
async def vm_audit(file: UploadFile = File(...), authorization: str = Header(None)):
    """
    Upload a GCP Service Account JSON file and audit VMs for public IPs.
    Requires JWT Bearer token in header.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.split(" ")[1]
    verify_token(token)

    try:
        content = await file.read()
        sa_info = json.loads(content)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON file uploaded.")

    return check_compute_public_ips(sa_info)
