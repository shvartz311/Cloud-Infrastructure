
resource "alicloud_oss_bucket" "bucket" {
  count  = var.module_enabled ? 1 : 0
  bucket = var.deploy_name
  acl    = var.acl

  server_side_encryption_rule {
    sse_algorithm = "AES256"
  }

  tags = {
    Name        = "${var.deploy_name}-${var.region}"
    Environment = var.environment
  }
}