resource "alicloud_kms_key" "kms" {
description             = "kms china beinig"
}
resource "alicloud_db_instance" "postgres" {
  for_each             = var.postgres_dbs_map
  instance_name        = lookup(each.value,"instance_name","null")
  engine               = lookup(each.value,"engine","PostgreSQL")
  engine_version       = lookup(each.value,"engine_version",14)
  instance_type        = lookup(each.value,"instance_type","pg.n2.medium.2c")
  instance_storage     = lookup(each.value,"instance_storage","30")
  vswitch_id           = join(",",var.vswitch_ids)
  monitoring_period    = lookup(each.value,"monitoring_period","60")
  security_ips         = var.security_ips
  instance_charge_type = var.instance_charge_type
  db_instance_storage_type = var.db_instance_storage_type
  resource_group_id    = var.resource_group_id
  zone_id              = var.zone_id
  zone_id_slave_a      = var.zone_id_slave_a
  security_group_ids   = var.security_group_ids
  storage_threshold    = var.storage_threshold
  encryption_key       = alicloud_kms_key.kms.id

}
resource "random_password" "k8s_database_password" {
  count       =  length(keys(var.postgres_dbs_map)) > 0 ?  1 : 0 
  length      = 16
  min_lower   = 2
  min_numeric = 2
  min_special = 2
  min_upper   = 2
  number      = true
  special     = true
  override_special = "!@#$%^&;*()_+-="
  upper       = true
}
resource "alicloud_rds_account" "db_account" {
 for_each          = var.postgres_dbs_map
  db_instance_id   = alicloud_db_instance.postgres[each.key].id
  account_name     = "postgres"
  account_password = random_password.k8s_database_password[0].result
}