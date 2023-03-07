output "k8s_connections" {
  value = alicloud_cs_managed_kubernetes.k8s[0].connections
}

# output "certificate_authority"{
#   value = alicloud_cs_managed_kubernetes.k8s[0].certificate_authority
# }
output "slb_intranet" {
    value = alicloud_cs_managed_kubernetes.k8s[0].slb_intranet
}
output "first_slb_listener_protocol" {
  value = data.alicloud_slb_listeners.sample_ds.slb_listeners[0].protocol
}
output "first_slb_id" {
  value = data.alicloud_slb_load_balancers.slb_lb.balancers[0].id
}

data "alicloud_slb_listeners" "sample_ds" {
  load_balancer_id = data.alicloud_slb_load_balancers.slb_lb.balancers[0].id
}
