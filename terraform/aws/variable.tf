variable "dome9-account-id" {
  default = "Dome9コンソールから確認できるAWSアカウントID"
}

variable "dome9-external-id" {
  default = "Dome9コンソールから確認できる外部ID"
}

output "dome9-external-id" {
  value = var.dome9-external-id
}
