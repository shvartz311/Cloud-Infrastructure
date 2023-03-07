variable "module_enabled" {
  default = true
}

variable "region" {
}

variable "deploy_name" {
}

variable "environment" {
}

variable "vpc_map" {
}

variable "is_sub_region" {
  default = false
}

variable "vpc_self_link" {
  default = ""
}

variable "private_route_table_ids" {
  default = ""
}
variable "vpc_cidr"{
  
}
variable "use_existing_nat_gateway"{
  default=false
}