
terraform {
  required_version = ">= 0.12"

  backend "s3" {
    bucket  = "バケット名"
    key     = "aws.tfstate"
    region  = "ap-northeast-1"
    encrypt = true
    acl     = "bucket-owner-full-control"
  }
}

provider "aws" {
  region = "ap-northeast-1"
}
