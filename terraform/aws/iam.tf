variable "dome9-account-id" {}
variable "dome9-external-id" {}

resource "aws_iam_role" "dome9-connect" {
  assume_role_policy    = data.aws_iam_policy_document.dome9-connect.json
  description           = "Dome9-Connect"
  force_detach_policies = false
  max_session_duration  = 3600
  name                  = "Dome9-Connect"
  path                  = "/"
  tags                  = {}
}

data "aws_iam_policy_document" "dome9-connect" {
  statement {
    actions = ["sts:AssumeRole"]
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.dome9-external-id]
    }
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.dome9-account-id}:root"]
    }
  }
}

resource "aws_iam_policy" "dome9-readonly-policy" {
  description = "dome9-readonly-policy"
  name        = "dome9-readonly-policy"
  path        = "/"
  policy      = data.aws_iam_policy_document.dome9-readonly-policy.json
}

data "aws_iam_policy_document" "dome9-readonly-policy" {
  statement {
    sid = "Dome9ReadOnly"
    actions = [
      "cloudtrail:LookupEvents",
      "dynamodb:DescribeTable",
      "elasticfilesystem:Describe*",
      "elasticache:ListTagsForResource",
      "firehose:Describe*",
      "firehose:List*",
      "guardduty:Get*",
      "guardduty:List*",
      "kinesis:List*",
      "kinesis:Describe*",
      "kinesisvideo:Describe*",
      "kinesisvideo:List*",
      "logs:Describe*",
      "logs:Get*",
      "logs:FilterLogEvents",
      "lambda:List*",
      "s3:List*",
      "sns:ListSubscriptions",
      "sns:ListSubscriptionsByTopic",
      "waf-regional:ListResourcesForWebACL"
    ]
    effect    = "Allow"
    resources = ["*"]
  }
}

resource "aws_iam_policy" "dome9-write-policy" {
  description = "dome9-write-policy"
  name        = "dome9-write-policy"
  path        = "/"
  policy      = data.aws_iam_policy_document.dome9-write-policy.json
}

data "aws_iam_policy_document" "dome9-write-policy" {
  statement {
    sid = "Dome9Write"
    actions = [
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:CreateSecurityGroup",
      "ec2:DeleteSecurityGroup",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:ModifyNetworkInterfaceAttribute",
      "ec2:CreateTags",
      "ec2:DeleteTags"
    ]
    effect    = "Allow"
    resources = ["*"]
  }
}

resource "aws_iam_policy" "dome9-iam-policy" {
  description = "dome9-iam-policy"
  name        = "dome9-iam-policy"
  path        = "/"
  policy      = data.aws_iam_policy_document.dome9-iam-policy.json
}

data "aws_iam_policy_document" "dome9-iam-policy" {
  statement {
    sid = "Dome9IAMConnectRead"
    actions = [
      "iam:Get*",
      "iam:List*"
    ]
    effect    = "Allow"
    resources = ["*"]
  }
  statement {
    sid = "Dome9IAMConnectRoles"
    actions = [
      "iam:AttachRolePolicy",
      "iam:DetachRolePolicy"
    ]
    condition {
      test     = "ArnEquals"
      variable = "iam:PolicyArn"
      values   = [aws_iam_policy.dome9-restricted-policy.arn]
    }
    effect    = "Allow"
    resources = ["*"]
  }
  statement {
    sid = "Dome9IAMConnectUserGroup"
    actions = [
      "iam:AddUserToGroup",
      "iam:RemoveUserFromGroup"
    ]
    effect    = "Allow"
    resources = [aws_iam_group.dome9-restricted-group.arn]
  }
}

resource "aws_iam_role_policy_attachment" "dome9-readonly-policy" {
  policy_arn = aws_iam_policy.dome9-readonly-policy.arn
  role       = aws_iam_role.dome9-connect.name
}

resource "aws_iam_role_policy_attachment" "dome9-write-policy" {
  policy_arn = aws_iam_policy.dome9-write-policy.arn
  role       = aws_iam_role.dome9-connect.name
}

resource "aws_iam_role_policy_attachment" "aws-securityaudit" {
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
  role       = aws_iam_role.dome9-connect.name
}

resource "aws_iam_role_policy_attachment" "aws-inspector-readonly-access" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonInspectorReadOnlyAccess"
  role       = aws_iam_role.dome9-connect.name
}
