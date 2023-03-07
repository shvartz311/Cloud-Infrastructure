variable "module_enabled" {
  default = true
}
variable "vpc_id" {
  
}
variable "deploy_name" {
}

variable "environment" {
}
variable "security_group_id" {
  
}
variable "vswitch_id" {
  type = string
}

variable "nas_cidrs" {
  default = []
}
variable "nfs_map" {
  
}
variable "file_system_description" {
  description = "The description of nas file system."
  default     = ""
}

variable "create_file_system" {
  description = "file system id the of file system."
  default     = false
}

variable "protocol_type" {
  description = "The protocol_type of file system."
  default     = "NFS"
}

variable "storage_type" {
  description = "The storage_type of file system."
  default     = "Performance"
}
variable "access_group_name" {
  description = "The access_group_name of access rule."
  default     = ""
}
variable "status"{
  default = "Active"
}
variable "access_group_type" {
  default = "Classic"
}

# variable "file_system_type" {
#  default = "extreme"
# }
variable "source_cidr_ip" {
  description = "The source_cidr_ip of an existing access rule."
  default     = ""
}

variable "rw_access_type" {
  description = "The rw_access_type of access rule."
  default     = "RDWR"
}

variable "user_access_type" {
  description = "The user_access_type of access rule."
  default     = "no_squash"
}

variable "access_rule_priority" {
  description = "The priority of access rule."
  default     = 1
}

variable "create_access_rule" {
  description = "The id of <access group name>:<access rule id>"
  default     = false
}
