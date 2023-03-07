resource "alicloud_resource_manager_resource_group" "resource_group" {
  count      = var.module_enabled ? 1 : 0 
 resource_group_name = "${var.deploy_name}-resourceGroup"
  display_name        = "${var.deploy_name}-resourceGroup" 
}

resource "alicloud_vpc" "vpc" {
  count      = var.module_enabled ? 1 : 0 
  vpc_name   = var.deploy_name
  cidr_block = var.vpc_cidr
  resource_group_id = alicloud_resource_manager_resource_group.resource_group[0].id
}
resource "alicloud_vswitch" "workers" {
  count             = var.module_enabled ? length(var.vpc_map.vswitch_cidrs.workers_vswitch) : 0
  vpc_id            = alicloud_vpc.vpc[0].id
  cidr_block        = var.vpc_map.vswitch_cidrs.workers_vswitch[count.index]
  zone_id            = var.vpc_map.availability_zones[count.index]
  vswitch_name              = length(var.vpc_map.vswitch_cidrs.workers_vswitch) > 1 ? "${alicloud_vpc.vpc[0].vpc_name}-workers" : "private"
  description       = "workers vswitch"
  tags = merge(
    {
      Name = format("%s%03d", "private", count.index + 1)
    },
  )
}

resource "alicloud_vswitch" "pods" {
  count             = var.module_enabled ? length(var.vpc_map.vswitch_cidrs.pods_vswitch) : 0
  vpc_id            = alicloud_vpc.vpc[0].id
  cidr_block        = var.vpc_map.vswitch_cidrs.pods_vswitch[count.index]
  zone_id            = var.vpc_map.availability_zones[count.index]
  vswitch_name      = length(var.vpc_map.vswitch_cidrs.pods_vswitch) > 1 ? "${alicloud_vpc.vpc[0].vpc_name}-pods" : "pods"
  description       = "pods vswitch"
  tags = merge(
    {
      Name = format("%s%03d", "pods-vswitch", count.index + 1)
    },
  )
}

resource "alicloud_vswitch" "database" {
  count             = var.module_enabled ? length(var.vpc_map.vswitch_cidrs.databases_vswitch) : 0
  vpc_id            = alicloud_vpc.vpc[0].id
  cidr_block        = var.vpc_map.vswitch_cidrs.databases_vswitch[count.index]
  zone_id            = var.vpc_map.availability_zones[count.index]
  vswitch_name              = length(var.vpc_map.vswitch_cidrs.databases_vswitch) > 1 ? "${alicloud_vpc.vpc[0].vpc_name}-databases" : "private"
  description       = "databases_vswitch"
  tags = merge(
    {
      Name = format("%s%03d", "private", count.index + 1)
    },
  )
}

resource "alicloud_vswitch" "public" {
  count             = var.module_enabled ? length(var.vpc_map.vswitch_cidrs.public_vswitch) : 0
  vpc_id            = alicloud_vpc.vpc[0].id
  cidr_block        = var.vpc_map.vswitch_cidrs.public_vswitch[count.index]
  zone_id            = var.vpc_map.availability_zones[count.index]
  vswitch_name              = length(var.vpc_map.vswitch_cidrs.public_vswitch) > 1 ? "${alicloud_vpc.vpc[0].vpc_name}-public" : "public"
  description       = "public_vswitch"
  tags = merge(
    {
      Name = format("%s%03d", "public-vswitch", count.index + 1)
    },
  )
}


resource "alicloud_nat_gateway" "this" {
  count                 = var.module_enabled ? 1 : 0
  vpc_id               = alicloud_vpc.vpc[0].id
  name                 = "${alicloud_vpc.vpc[0].vpc_name}-natgateway"
  description          = "A Nat Gateway."
  payment_type         = "PayAsYouGo"
  nat_type             = "Enhanced"
  vswitch_id           = alicloud_vswitch.public[0].id
}

resource "alicloud_eip_address" "default" {
  count        = 2
  address_name = "${alicloud_vpc.vpc[0].vpc_name}-eip-${count.index}"
}

resource "alicloud_eip_association" "default" {
  count         = 2
  allocation_id = element(alicloud_eip_address.default.*.id, count.index)
  instance_id   = alicloud_nat_gateway.this[0].id
}

resource "alicloud_common_bandwidth_package" "default" {
  bandwidth_package_name   = "${alicloud_vpc.vpc[0].vpc_name}-bandwidth-packge"
  bandwidth                 = 10
  internet_charge_type      = "PayByTraffic"
  ratio                     = 100
}

resource "alicloud_common_bandwidth_package_attachment" "default" {
  count                = 2
  bandwidth_package_id = alicloud_common_bandwidth_package.default.id
  instance_id          = element(alicloud_eip_address.default.*.id, count.index)
}

resource "alicloud_snat_entry" "default" {
  depends_on        = [alicloud_eip_association.default]
  snat_table_id     = alicloud_nat_gateway.this[0].snat_table_ids
  #source_vswitch_id = alicloud_vswitch[0].id
  source_cidr       = "10.210.0.0/16"
  snat_ip           = join(",", alicloud_eip_address.default.*.ip_address)
}

