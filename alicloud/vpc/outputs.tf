output "vpc_id" {
  value = alicloud_vpc.vpc[0].id
}


output "workers_cidr_blocks" {
  value = alicloud_vswitch.workers.*.cidr_block
}
output "pods_cidr_blocks" {
  value = alicloud_vswitch.pods.*.cidr_block
}
output "databases_cidr_blocks" {
  value = alicloud_vswitch.database.*.cidr_block
}
output "public_cidr_blocks" {
  value = alicloud_vswitch.public.*.cidr_block
}

output "workers_vswitch_ids" {
  value = alicloud_vswitch.workers.*.id
}
output "pods_vswitch_ids" {
  value = alicloud_vswitch.pods.*.id
}
output "databases_vswitch_ids" {
  value = alicloud_vswitch.database.*.id
}

output "databases_vswitch_id_0" {
  value = alicloud_vswitch.database[0].id
}

output "databases_vswitch_id_1" {
  value = alicloud_vswitch.database[0].id
}
output "databases_vswitch_id_2" {
  value = alicloud_vswitch.database[2].id
}
output "databases_vswitch_zones" {
  value = alicloud_vswitch.database.*.availability_zone
}
output "public_vswitch_ids" {
  value = alicloud_vswitch.public.*.id
}

output "nat_gateway" {
  value = alicloud_nat_gateway.this.*.id
}
output "resource_group_id" {
value = alicloud_resource_manager_resource_group.resource_group[0].id
}

output "vpc_cidr" {
  value=alicloud_vpc.vpc.*.cidr_block
}