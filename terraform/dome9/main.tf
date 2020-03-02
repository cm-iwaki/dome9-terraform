
terraform {
  required_version = ">= 0.12"

  backend "s3" {
    bucket  = "バケット名"
    key     = "dome9.tfstate"
    region  = "ap-northeast-1"
    encrypt = true
    acl     = "bucket-owner-full-control"
  }
}

provider "dome9" {
  dome9_access_id  = var.access_id
  dome9_secret_key = var.secret_key
}
