from googleapiclient import discovery


def check_compute_public_ips(creds, project):
    compute = discovery.build('compute', 'v1', credentials=creds)
    results = []

    request = compute.instances().aggregatedList(project=project)
    while request is not None:
        response = request.execute()

        for _, instances_scoped in response.get('items', {}).items():
            for instance in instances_scoped.get('instances', []):
                for iface in instance.get('networkInterfaces', []):
                    access = iface.get('accessConfigs', [])
                    for cfg in access:
                        if "natIP" in cfg:
                            results.append({
                                "instance": instance["name"],
                                "public_ip": cfg["natIP"]
                            })
        request = compute.instances().aggregatedList_next(
            previous_request=request, previous_response=response
        )

    return results


def check_sql_public_ips(creds, project):
    sql = discovery.build('sqladmin', 'v1beta4', credentials=creds)
    response = sql.instances().list(project=project).execute()

    results = []
    for inst in response.get("items", []):
        if inst.get("ipAddresses"):
            for ip in inst["ipAddresses"]:
                if ip["type"] == "PRIMARY":
                    results.append({
                        "instance": inst["name"],
                        "public_ip": ip["ipAddress"]
                    })
    return results


def check_gke_clusters(creds, project):
    gke = discovery.build("container", "v1", credentials=creds)
    req = gke.projects().locations().clusters().list(parent=f"projects/{project}/locations/-")
    resp = req.execute()

    return resp.get("clusters", [])


def check_owner_service_accounts(creds, project):
    iam = discovery.build("iam", "v1", credentials=creds)
    req = iam.projects().serviceAccounts().list(name=f"projects/{project}")
    resp = req.execute()

    return resp.get("accounts", [])


def check_public_buckets(creds, project):
    storage = discovery.build("storage", "v1", credentials=creds)
    resp = storage.buckets().list(project=project).execute()

    return resp.get("items", [])


def check_firewall_rules(creds, project):
    compute = discovery.build("compute", "v1", credentials=creds)
    resp = compute.firewalls().list(project=project).execute()

    return resp.get("items", [])


def check_load_balancers_audit(creds, project):
    compute = discovery.build("compute", "v1", credentials=creds)
    resp = compute.forwardingRules().aggregatedList(project=project).execute()

    return resp.get("items", [])


def check_cloud_functions_and_run(creds, project):
    cloudrun = discovery.build('run', 'v1', credentials=creds)
    resp = cloudrun.projects().locations().services().list(
        parent=f"projects/{project}/locations/-"
    ).execute()

    return resp.get("items", [])
