import json
import boto3
import os

sns = boto3.client("sns")
TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")

def lambda_handler(event, context):
    print("Received event:", json.dumps(event))
    
    detail = event.get("detail", {})
    message = f"⚠️ Suspicious activity detected!\nEvent: {detail.get('eventName')}\nUser: {detail.get('userIdentity', {}).get('arn')}"
    
    response = sns.publish(
        TopicArn=TOPIC_ARN,
        Message=message,
        Subject="AWS Threat Detection Alert"
    )
    
    return {"statusCode": 200, "body": "Alert sent."}
