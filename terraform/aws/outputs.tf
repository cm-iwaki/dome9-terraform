output "dome9-external-id" {
  value = var.dome9-external-id
}

output "dome9-connect-role-arn" {
  value = aws_iam_role.dome9-connect.arn
}
