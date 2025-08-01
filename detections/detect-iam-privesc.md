# IAM Privilege Escalation Detection

This detection monitors CloudTrail for `AttachRolePolicy`, `PutUserPolicy`, and `CreatePolicyVersion`. These actions can indicate attempts to escalate privileges via IAM roles or users.
