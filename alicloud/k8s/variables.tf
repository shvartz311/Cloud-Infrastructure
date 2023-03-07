variable "cluster_addons" {
  type = list(object({
    name      = string
    config    = string
  }))
  default = [
    {
    "name"       = "terway-eniip",
    "config"     = ""
    },
    {
      "name"     = "logtail-ds",
      "config"   = "{\"IngressDashboardEnabled\":\"true\",\"sls_project_name\":\"your-sls-project-name\"}",
    },
  ]
}
variable "worker_vswitch_ids"{
    
}
variable "rds_instances"{
default = []   
}
variable "security_group_ids"{
default =[] 
}
variable "security_group_id"{
default =[] 
}
variable "workder_disk_category"{
default = "cloud_ssd"
}
variable "pod_vswitch_ids" {
  
}
variable "nat_gateway_id" {

}
variable "deploy_name" {
  
}
variable "new_nat_gateway" {
  default = false
}
variable "cluster_spec"{
default = "ack.pro.small"
}
variable "k8s_map" {

}
variable "enable_ssh"{
default = true
}
variable "vpc_id" {
  
}
variable "module_enabled" {
  
}
variable "service_cidr" {
default = "172.19.0.0/20"
}
variable "resource_group_id" {

}