resource "alicloud_cs_managed_kubernetes" "k8s" {
  count                 = var.module_enabled ? 1 : 0
  name                  = var.deploy_name
  version               = lookup(var.k8s_map.override,"k8s_version","1.20.11-aliyun.1")
  pod_vswitch_ids       = var.pod_vswitch_ids
  cluster_spec          = var.cluster_spec
  security_group_id     = var.security_group_id
  #is_enterprise_security_group = true
  service_cidr          = var.service_cidr
  worker_vswitch_ids    = var.worker_vswitch_ids
  new_nat_gateway       = var.new_nat_gateway
  resource_group_id     = var.resource_group_id 
  slb_internet_enabled = true
  enable_ssh            = var.enable_ssh
   dynamic "addons" {
      for_each = var.cluster_addons
      content {
        name          = lookup(addons.value, "name", var.cluster_addons)
        config        = lookup(addons.value, "config", var.cluster_addons)
      }
  }

}

data "alicloud_instance_types" "default" { //should be modify 
  cpu_core_count       = 2
  memory_size          = 4
  kubernetes_node_role = "Worker"
}
resource "alicloud_cs_kubernetes_node_pool" "default" {
  count                = contains(keys(var.k8s_map),"default") ? 1 : 0 
  name                 = lookup(var.k8s_map.default,"name","default")
  cluster_id           = alicloud_cs_managed_kubernetes.k8s[0].id
  instance_types       = lookup(var.k8s_map.default,"instance_types",["ecs.g6e.large"])
  system_disk_category = lookup(var.k8s_map.default,"system_disk_category","cloud_essd")
  system_disk_size     = lookup(var.k8s_map.default,"system_disk_size",40)
  key_name             = var.deploy_name
  resource_group_id     = var.resource_group_id 
  vswitch_ids          = var.worker_vswitch_ids
  node_count = 1
  data_disks {
    category = "cloud_essd"
    encrypted = true
    size = lookup(var.k8s_map.ft,"data_disk_size",40)
  }
  # scaling_config {
  #  min_size = lookup(var.k8s_map.ft,"min_size","1") 
  #  max_size = lookup(var.k8s_map.ft,"max_size","3") 
  # }
 security_group_ids = concat(var.security_group_ids,[var.security_group_id])
}

resource "alicloud_cs_kubernetes_node_pool" "ft" {
  count                = contains(keys(var.k8s_map),"ft") ? 1 : 0 
  name                 = lookup(var.k8s_map.ft,"name","ft-01")
  cluster_id           = alicloud_cs_managed_kubernetes.k8s[0].id
  instance_types       = lookup(var.k8s_map.ft,"instance_types",["ecs.g6e.large"])
  system_disk_category = lookup(var.k8s_map.ft,"system_disk_category","cloud_essd")
  system_disk_size     = lookup(var.k8s_map.ft,"system_disk_size",40)
  key_name             = var.deploy_name
  resource_group_id     = var.resource_group_id 
  vswitch_ids          = var.worker_vswitch_ids
  data_disks {
    category = "cloud_essd"
    encrypted = true
    size = lookup(var.k8s_map.ft,"data_disk_size",40)
  }
  scaling_config {
   min_size = lookup(var.k8s_map.ft,"min_size","1") 
   max_size = lookup(var.k8s_map.ft,"max_size","3") 
  }
 security_group_ids = concat(var.security_group_ids,[var.security_group_id])
}

resource "alicloud_cs_kubernetes_node_pool" "ng" {
  count                = contains(keys(var.k8s_map),"ng") ? 1 : 0 
  name                 = lookup(var.k8s_map.ng,"name","ng-01")
  cluster_id           = alicloud_cs_managed_kubernetes.k8s[0].id
  instance_types       = lookup(var.k8s_map.ng,"instance_types",["ecs.g6e.large"])
  system_disk_category = lookup(var.k8s_map.ng,"system_disk_category","cloud_essd")
  system_disk_size     = lookup(var.k8s_map.ng,"system_disk_size",40)
  key_name             = var.deploy_name
  resource_group_id     = var.resource_group_id 
  vswitch_ids          = var.worker_vswitch_ids
  data_disks {
    category = "cloud_essd"
    encrypted = true
    size = lookup(var.k8s_map.ng,"data_disk_size",40)
  }
  scaling_config {
   min_size = lookup(var.k8s_map.ng,"min_size","1") 
   max_size = lookup(var.k8s_map.ng,"max_size","3") 
  }
 security_group_ids = concat(var.security_group_ids,[var.security_group_id])
}




data "alicloud_slb_load_balancers" "slb_lb" {
address = alicloud_cs_managed_kubernetes.k8s[0].slb_intranet
}


