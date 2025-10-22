import boto3
import random

# Initialize DynamoDB resource
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("birthday-integration-app-members")

def update_items(response):
    for item in response["Items"]:
        code = str(random.randint(10000, 99999))
        table.update_item(
            Key={"member": item["member"]},
            UpdateExpression="SET #c = :val",
            ExpressionAttributeNames={"#c": "code"},
            ExpressionAttributeValues={":val": code},
        )
        print(f"Updated {item['member']} with code {code}")

# Initial scan
response = table.scan()
update_items(response)

# Handle pagination (if table has more than 1MB of items)
while "LastEvaluatedKey" in response:
    response = table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
    update_items(response)
