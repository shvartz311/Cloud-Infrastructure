output "sshproxy_ip_address" {
  value = alicloud_eip_address.sshproxy_eip.*.ip_address
}