output "sshproxy-sg" {
  value = alicloud_security_group.sshproxy[0].id   
}

output "k8s-sg" {
  value = alicloud_security_group.k8s_security_group[0].id
}
output "postgres-sg"{
  value = alicloud_security_group.postgres[0].id  
}
output "nfs-sg"{
  value = alicloud_security_group.nfs[0].id  
}