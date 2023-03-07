resource "alicloud_security_group" "k8s_security_group" {
  count               =  contains(keys(var.sg_map),"k8s") ?  1 : 0 
  name                = lookup(var.sg_map.k8s,"name","k8s-sg")
  vpc_id              = var.vpc_id
  resource_group_id   =var.resource_group_id 
  security_group_type = lookup(var.sg_map.k8s,"security_group_type","normal")
  inner_access_policy = lookup(var.sg_map.k8s,"inner_access_policy","Accept")
  #tags = lookup(var.sg_map.k8s,"tags","")
}

resource "alicloud_security_group_rule" "k8s_group_rule" {
  count            =  contains(keys(var.sg_map),"k8s") ?  1 : 0 
  type              = lookup(var.sg_map.k8s.sg-rule,"ingress","ingress")
  ip_protocol       = lookup(var.sg_map.k8s.sg-rule,"ip_protocol","tcp")
  nic_type          = lookup(var.sg_map.k8s.sg-rule,"nic_type","intranet")
  policy            = lookup(var.sg_map.k8s.sg-rule,"policy","accept")
  port_range        = lookup(var.sg_map.k8s.sg-rule,"port_range","443/443")
  priority          = lookup(var.sg_map.k8s.sg-rule,"priority","1")
  security_group_id = lookup(var.sg_map.k8s.sg-rule,"security_group_id",alicloud_security_group.k8s_security_group[0].id)
  cidr_ip           = lookup(var.sg_map.k8s.sg-rule,"cidr_ip","10.210.0.0/16")
}

resource "alicloud_security_group" "sshproxy" {
  count               = contains(keys(var.sg_map),"sshproxy") ?  1 : 0 
  name                = lookup(var.sg_map.sshproxy,"name","sshproxy-sg")
  vpc_id              = var.vpc_id
  resource_group_id   = var.resource_group_id 
  security_group_type = lookup(var.sg_map.sshproxy,"security_group_type","normal")
  inner_access_policy = lookup(var.sg_map.sshproxy,"inner_access_policy","Accept")
}

resource "alicloud_security_group_rule" "sshproxy_group_rule" {
  for_each          = toset(var.ssh_source_ranges)
  type              = lookup(var.sg_map.sshproxy.sg-rule,"ingress","ingress")
  ip_protocol       = lookup(var.sg_map.sshproxy.sg-rule,"ip_protocol","udp")
  nic_type          = lookup(var.sg_map.sshproxy.sg-rule,"nic_type","intranet")
  policy            = lookup(var.sg_map.sshproxy.sg-rule,"policy","accept")
  port_range        = lookup(var.sg_map.sshproxy.sg-rule,"port_range","22/22")
  priority          = lookup(var.sg_map.sshproxy.sg-rule,"priority","1")
  security_group_id = lookup(var.sg_map.sshproxy.sg-rule,"security_group_id",alicloud_security_group.sshproxy[0].id)
  cidr_ip           = each.key
}

resource "alicloud_security_group" "postgres" {
  count               = contains(keys(var.sg_map),"postgres") ?  1 : 0 
  name                = lookup(var.sg_map.postgres,"name","sshproxy-sg")
  vpc_id              = var.vpc_id
  resource_group_id   =var.resource_group_id 
  security_group_type = lookup(var.sg_map.postgres,"security_group_type","normal")
  inner_access_policy = lookup(var.sg_map.postgres,"inner_access_policy","Accept")
}

resource "alicloud_security_group_rule" "postgres_allow_from_ssh" {
  count             = contains(keys(var.sg_map.postgres),"sg-rule-allow-from-sshproxy") ?  1 : 0 
  type              = lookup(var.sg_map.postgres.sg-rule-allow-from-sshproxy,"ingress","ingress")
  ip_protocol       = lookup(var.sg_map.postgres.sg-rule-allow-from-sshproxy,"ip_protocol","udp")
  nic_type          = lookup(var.sg_map.postgres.sg-rule-allow-from-sshproxy,"nic_type","intranet")
  policy            = lookup(var.sg_map.postgres.sg-rule-allow-from-sshproxy,"policy","accept")
  port_range        = lookup(var.sg_map.postgres.sg-rule-allow-from-sshproxy,"port_range","5432/5432")
  priority          = lookup(var.sg_map.postgres.sg-rule-allow-from-sshproxy,"priority","1")
  security_group_id = alicloud_security_group.postgres[0].id
  source_security_group_id = alicloud_security_group.sshproxy[0].id
}

resource "alicloud_security_group_rule" "postgres_allow_from_k8s" {
  count             = contains(keys(var.sg_map.postgres),"sg-rule-allow-from-k8s") ?  1 : 0 
  type              = lookup(var.sg_map.postgres.sg-rule-allow-from-k8s,"ingress","ingress")
  ip_protocol       = lookup(var.sg_map.postgres.sg-rule-allow-from-k8s,"ip_protocol","udp")
  nic_type          = lookup(var.sg_map.postgres.sg-rule-allow-from-k8s,"nic_type","intranet")
  policy            = lookup(var.sg_map.postgres.sg-rule-allow-from-k8s,"policy","accept")
  port_range        = lookup(var.sg_map.postgres.sg-rule-allow-from-k8s,"port_range","5432/5432")
  priority          = lookup(var.sg_map.postgres.sg-rule-allow-from-k8s,"priority","1")
  security_group_id = alicloud_security_group.postgres[0].id
  source_security_group_id = alicloud_security_group.k8s_security_group[0].id
}

resource "alicloud_security_group" "nfs" {
  count                = contains(keys(var.sg_map),"nfs") ?  1 : 0 
  name                 = lookup(var.sg_map.nfs,"name","nfs-sg")
  vpc_id               = var.vpc_id
  resource_group_id     =var.resource_group_id 
  security_group_type = lookup(var.sg_map.nfs,"security_group_type","normal")
  inner_access_policy = lookup(var.sg_map.nfs,"inner_access_policy","Accept")
}

resource "alicloud_security_group_rule" "nfs_allow_from_k8s" {
  count             = contains(keys(var.sg_map),"nfs")   ?  1 : 0 
  type              = lookup(var.sg_map.nfs.sg-rule,"ingress","ingress")
  ip_protocol       = lookup(var.sg_map.nfs.sg-rule,"ip_protocol","udp")
  nic_type          = lookup(var.sg_map.nfs.sg-rule,"nic_type","intranet")
  policy            = lookup(var.sg_map.nfs.sg-rule,"policy","accept")
  port_range        = lookup(var.sg_map.nfs.sg-rule,"port_range","2049/2049")
  priority          = lookup(var.sg_map.nfs.sg-rule,"priority","1")
  security_group_id = alicloud_security_group.nfs[0].id
  source_security_group_id = alicloud_security_group.k8s_security_group[0].id
}