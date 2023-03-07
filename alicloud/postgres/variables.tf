
  variable "resource_group_id" {
    
  }
  variable "postgres_dbs_map" {
    
  }

  variable "security_group_ids"{
  
  }

  variable "storage_auto_scale"{
    default = "Enable"
  }
  variable "storage_threshold" {
      default = 50    
  }

variable "security_ips" {
  type=list(string)
  default = ["10.210.0.0/16","127.0.0.1"]
}
variable "db_instance_storage_type" {
    default = "cloud_essd"
}
variable "vswitch_ids" {
  
}

variable "instance_charge_type"{
default = "Postpaid"
}


  variable "zone_id" {
    
  }

  variable "zone_id_slave_a"{

  }