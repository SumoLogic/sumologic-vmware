from vmware.vapi.vsphere.client import create_vsphere_client

def get_tags_for_vm(vcenter_host, username, password):
    client = create_vsphere_client(
        server=vcenter_host,
        username=username,
        password=password,
        session=None)

    cat_dict = {}
    for id in client.tagging.Category.list():
        cat = client.tagging.Category.get(id)
        cat_dict[cat.id] = cat.name

    tag_dict = {}
    for id in client.tagging.Tag.list():
        tag = client.tagging.Tag.get(id)
        tag_dict[id] = tag

    vms = client.vcenter.VM.list()
    vm_objs = [{'id': v.vm, 'type': 'VirtualMachine'} for v in vms]

    vm_tags = {}
    for vm in client.tagging.TagAssociation.list_attached_tags_on_objects(vm_objs):
        cat_tag_dict = {}
        for ti in vm.tag_ids:
            cat_name = cat_dict[tag_dict[ti].category_id]
            if cat_name not in cat_tag_dict:
                cat_tag_dict[cat_name] = []
            cat_tag_dict[cat_name].append(tag_dict[ti].name)
        vm_name = ""
        for v in vms:
            if v.vm == vm.object_id.id:
                vm_name = v.name
                break
        vm_tags[vm_name] = cat_tag_dict
    print(f"here is the list of vm_tags fetched from rest api client = {vm_tags}")
    return vm_tags