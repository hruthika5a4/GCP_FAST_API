from googleapiclient import discovery
from google.auth import default

def check_compute_public_ips(project_id):
    creds, _ = default()
    compute = discovery.build('compute', 'v1', credentials=creds)
    vm_data = []

    req = compute.instances().aggregatedList(project=project_id)
    while req is not None:
        res = req.execute()
        for zone, scoped_list in res.get('items', {}).items():
            for instance in scoped_list.get('instances', []):
                name = instance['name']
                for nic in instance.get('networkInterfaces', []):
                    for ac in nic.get('accessConfigs', []):
                        if 'natIP' in ac:
                            vm_data.append({
                                "vm_name": name,
                                "zone": zone,
                                "public_ip": ac["natIP"]
                            })
        req = compute.instances().aggregatedList_next(req, res)
    
    return vm_data
