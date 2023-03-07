
data "alicloud_images" "ubuntu" {
  most_recent = true
  name_regex  = "^ubuntu_20.*64"
}

resource "alicloud_instance" "sshproxy" {
  count                               = var.module_enabled ? var.number_of_instances : 0
  image_id                            = lookup(var.sshproxy_map,"image_id",data.alicloud_images.ubuntu.ids.0)
  instance_type                       = lookup(var.sshproxy_map,"instance_type","ecs.c6e.large")
  security_groups                     = var.security_group_ids
  vswitch_id                          = element(distinct(compact(concat([var.vswitch_id], var.vswitch_ids))), count.index, )
  instance_name                       = lookup(var.sshproxy_map,"instance_name","${var.deploy_name}-sshproxy")
  host_name                           = lookup(var.sshproxy_map,"host_name","${var.deploy_name}-sshproxy")
  resource_group_id                   = var.resource_group_id
  internet_charge_type                = var.internet_charge_type
  system_disk_category                = var.system_disk_category
  system_disk_size                    = var.system_disk_size
  #internet_max_bandwidth_out          = var.internet_max_bandwidth_out
  system_disk_auto_snapshot_policy_id = var.system_disk_auto_snapshot_policy_id
  dynamic "data_disks" {
    for_each = var.data_disks
    content {
      name                    = lookup(data_disks.value, "name", var.disk_name)
      size                    = lookup(data_disks.value, "size", var.disk_size)
      category                = lookup(data_disks.value, "category", var.disk_category)
      encrypted               = lookup(data_disks.value, "encrypted", null)
      snapshot_id             = lookup(data_disks.value, "snapshot_id", null)
      delete_with_instance    = lookup(data_disks.value, "delete_with_instance", null)
      description             = lookup(data_disks.value, "description", null)
      auto_snapshot_policy_id = lookup(data_disks.value, "auto_snapshot_policy_id", null)
    }
  }

  user_data                     = var.user_data
  role_name                     = var.role_name
  key_name                      = var.key_name
  deletion_protection           = var.deletion_protection
  force_delete                  = var.force_delete
  security_enhancement_strategy = var.security_enhancement_strategy
}

resource "alicloud_eip_address" "sshproxy_eip" {
count         = var.module_enabled ? var.number_of_instances : 0
resource_group_id = var.resource_group_id
internet_charge_type = var.internet_charge_type

}

resource "alicloud_eip_association" "sshproxy_eip_association" {
  count         = var.module_enabled ? var.number_of_instances : 0
  allocation_id = alicloud_eip_address.sshproxy_eip[count.index].id
  instance_id   = alicloud_instance.sshproxy[count.index].id
}
