# 🔐 AWS Threat Detection Lab

Welcome to the AWS Threat Detection Lab a hands-on project showcasing how to detect, alert, and respond to security threats in AWS using native services and minimal custom code. This lab simulates real-world attack scenarios and provides infrastructure and logic to detect them in real-time.

---

## 🧭 Overview

This project demonstrates how to:

- Simulate AWS threat activity like IAM privilege escalation
- Log and detect that activity using **CloudTrail** and a targeted **EventBridge** rule (see [`detections/detect-iam-privesc.md`](detections/detect-iam-privesc.md))
- Route matching findings to a **Lambda** function that alerts via **SNS**
- Deploy everything with **Terraform** for reproducibility

GuardDuty and Security Hub are natural extensions of this lab (both can route findings to the same EventBridge + Lambda + SNS pipeline) but are not currently provisioned by the Terraform here.

---

## 🧰 Services Used

| Service           | Purpose                                  |
|------------------|------------------------------------------|
| CloudTrail        | Logs AWS API activity                    |
| EventBridge       | Routes detection events in real-time     |
| Lambda            | Sends custom alerts on suspicious events |
| SNS               | Delivers alerts (email, Slack, SMS, etc) |
| Terraform         | Infrastructure as Code                   |
