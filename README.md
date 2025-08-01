# 🔐 AWS Threat Detection Lab

Welcome to the AWS Threat Detection Lab a hands-on project showcasing how to detect, alert, and respond to security threats in AWS using native services and minimal custom code. This lab simulates real-world attack scenarios and provides infrastructure and logic to detect them in real-time.

---

## 🧭 Overview

This project demonstrates how to:

- Simulate AWS threat activity like privilege escalation and suspicious logins
- Detect malicious activity using **AWS GuardDuty**, **CloudTrail**, and **Security Hub**
- Route findings to **EventBridge**, trigger **Lambda alerts**, and notify via **SNS**
- Deploy everything with **Terraform** for reproducibility

---

## 🧰 Services Used

| Service           | Purpose                                  |
|------------------|------------------------------------------|
| CloudTrail        | Logs AWS API activity                    |
| GuardDuty         | Detects anomalies and known attack types |
| Security Hub      | Aggregates and normalizes security data  |
| EventBridge       | Routes detection events in real-time     |
| Lambda            | Sends custom alerts on suspicious events |
| SNS               | Delivers alerts (email, Slack, SMS, etc) |
| Terraform         | Infrastructure as Code                   |
## 📁 Project Structure

