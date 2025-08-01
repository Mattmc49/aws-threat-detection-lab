provider "aws" {
  region = var.aws_region
}

resource "aws_cloudtrail" "main" {
  name                          = "threat-detection-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.id
  include_global_service_events = true
  is_multi_region_trail        = true
  enable_logging                = true
}

resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket = "cloudtrail-threat-detection-logs"
}

resource "aws_sns_topic" "alert_topic" {
  name = "security-alerts"
}

resource "aws_lambda_function" "suspicious_alert" {
  filename         = "../lambda/suspicious_activity_alert/function.zip"
  function_name    = "SuspiciousActivityAlert"
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.9"
  role             = aws_iam_role.lambda_exec.arn
  source_code_hash = filebase64sha256("../lambda/suspicious_activity_alert/function.zip")
}

resource "aws_iam_role" "lambda_exec" {
  name = "lambda-threat-alert-exec"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.suspicious_alert.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.suspicious_activity.arn
}

resource "aws_cloudwatch_event_rule" "suspicious_activity" {
  name        = "SuspiciousActivityEvent"
  description = "Triggers on suspicious IAM or S3 API activity"
  event_pattern = jsonencode({
    source = ["aws.iam", "aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["AttachRolePolicy", "PutBucketPolicy"]
    }
  })
}

resource "aws_cloudwatch_event_target" "send_to_lambda" {
  rule      = aws_cloudwatch_event_rule.suspicious_activity.name
  target_id = "SendToLambda"
  arn       = aws_lambda_function.suspicious_alert.arn
}
