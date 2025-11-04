from googleapiclient import discovery
from google.auth import default

# ✅ Get credentials once — reuse everywhere
creds, project_from_creds = default()

# ✅ Helper to always choose ENV var first
import os
def get_project_id():
    return os.getenv("PROJECT_ID") or project_from_creds


# ----------------- Compute VM Public IPs -----------------
def check_compute_public_ips():
    project = get_project_id()
    compute = discovery.build('compute', 'v1', credentials=creds)
    
    vm_data = []
    req = compute.instances().aggregatedList(project=project)

    while req is not None:
        res = req.execute()
        for zone, scoped_list in res.get('items', {}).items():
            for instance in scoped_list.get('instances', []):
                name = instance['name']
                for nic in instance.get('networkInterfaces', []):
                    for ac in nic.get('accessConfigs', []):
                        if 'natIP' in ac:
                            vm_data.append([name, zone, ac['natIP']])
        req = compute.instances().aggregatedList_next(req, res)

    return vm_data


# ----------------- SQL Public IPs -----------------
def check_sql_public_ips():
    project = get_project_id()
    sqladmin = discovery.build('sqladmin', 'v1beta4', credentials=creds)

    sql_data = []
    req = sqladmin.instances().list(project=project)
    res = req.execute()

    for instance in res.get('items', []):
        for ip in instance.get('ipAddresses', []):
            if ip.get('type') == 'PRIMARY':
                sql_data.append([instance['name'], ip.get('ipAddress', 'N/A')])

    return sql_data


# ----------------- GKE Cluster Public Endpoints -----------------
def check_gke_clusters():
    project = get_project_id()
    container = discovery.build('container', 'v1', credentials=creds)

    gke_data = []
    req = container.projects().locations().clusters().list(parent=f"projects/{project}/locations/-")
    res = req.execute()

    for cluster in res.get('clusters', []):
        endpoint = cluster.get('endpoint', '')
        private_nodes = cluster.get('privateClusterConfig', {}).get('enablePrivateNodes', False)

        if endpoint and not private_nodes:
            gke_data.append([cluster['name'], endpoint])

    return gke_data


# ----------------- Owner Service Accounts -----------------
def check_owner_service_accounts():
    project = get_project_id()
    crm = discovery.build('cloudresourcemanager', 'v1', credentials=creds)

    owner_data = []
    policy = crm.projects().getIamPolicy(resource=project, body={}).execute()

    for binding in policy.get('bindings', []):
        if binding.get('role') == 'roles/owner':
            for member in binding.get('members', []):
                if member.startswith("serviceAccount:"):
                    owner_data.append([member, binding['role']])

    return owner_data


# ----------------- Public Buckets -----------------
def check_public_buckets():
    project = get_project_id()
    storage = discovery.build('storage', 'v1', credentials=creds)

    bucket_data = []
    res = storage.buckets().list(project=project).execute()

    for bucket in res.get('items', []):
        try:
            iam = storage.buckets().getIamPolicy(bucket=bucket['name']).execute()
            for b in iam.get('bindings', []):
                for m in b.get('members', []):
                    if 'allUsers' in m or 'allAuthenticatedUsers' in m:
                        bucket_data.append([bucket['name'], b['role'], m])
        except:
            continue

    return bucket_data
