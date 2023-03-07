resource "alicloud_nas_file_system" "nfs" {
  count         = var.module_enabled ? 1 : 0
  file_system_type= lookup(var.nfs_map,"file_system_type","standard")
  protocol_type = lookup(var.nfs_map,"protocol_type","NFS")
  storage_type  = lookup(var.nfs_map,"storage_type","Performance")
  encrypt_type  = lookup(var.nfs_map,"encrypt_type",1) // 1 means encrypt with managed key
  vpc_id        = var.vpc_id
  vswitch_id    = var.vswitch_id
}

resource "alicloud_nas_access_rule" "access_rule" {
  count             = var.module_enabled ? 1 : 0
  access_group_name = alicloud_nas_access_group.access_group[0].name
  source_cidr_ip    = var.source_cidr_ip //allow access from the source cidr ip
  rw_access_type    = var.rw_access_type
  user_access_type  = var.user_access_type
  priority          = var.access_rule_priority
}

resource "alicloud_nas_mount_target" "mount_target" {
count             = var.module_enabled ? 1 : 0
file_system_id    = alicloud_nas_file_system.nfs[0].id
access_group_name = alicloud_nas_access_group.access_group[0].access_group_name
vswitch_id        = var.vswitch_id
status            = var.status
security_group_id = var.security_group_id
}
   
resource "alicloud_nas_access_group" "access_group" {
  count              = var.module_enabled ? 1 : 0
  name               = "${var.deploy_name}-nas-access-group"
  type               =  var.access_group_type
}