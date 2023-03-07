output "db_connection_string" {
  value = tomap({ 
       for k,v in alicloud_db_instance.postgres : k => v.connection_string
  })
}

output "postgres_admin_username" {
    value = tomap({ 
       for k,v in alicloud_rds_account.db_account : k => v.account_name
  })
}

output "postgres_admin_password" {
   value = tomap({ 
       for k,v in alicloud_rds_account.db_account : k => v.account_password
  })

}