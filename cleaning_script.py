#!/usr/bin/env python3
import boto3
from botocore.exceptions import BotoCoreError, ClientError

# --- CONFIGURATION ---
REGION = "eu-central-1"
TEAMS_TABLE = "birthday-integration-app-teams"
MEMBERS_TABLE = "birthday-integration-app-members"
QUESTIONS_TABLE = "birthday-integration-app-questions"
# ----------------------

session = boto3.Session(region_name=REGION)
dynamodb = session.resource("dynamodb")

teams_table = dynamodb.Table(TEAMS_TABLE)
members_table = dynamodb.Table(MEMBERS_TABLE)
questions_table = dynamodb.Table(QUESTIONS_TABLE)


def scan_all(table):
    """Yield all items from a DynamoDB table via paginated scan."""
    exclusive_start_key = None
    while True:
        params = {}
        if exclusive_start_key:
            params["ExclusiveStartKey"] = exclusive_start_key
        resp = table.scan(**params)
        for item in resp.get("Items", []):
            yield item
        exclusive_start_key = resp.get("LastEvaluatedKey")
        if not exclusive_start_key:
            break


def reset_teams():
    """Set players=[] for every team item."""
    count = 0
    print(f"Resetting players list for all teams in {TEAMS_TABLE}...")
    for item in scan_all(teams_table):
        team_name = item.get("team_name")
        if not team_name:
            continue
        teams_table.update_item(
            Key={"team_name": team_name},
            UpdateExpression="SET #players = :empty",
            ExpressionAttributeNames={"#players": "players"},
            ExpressionAttributeValues={":empty": []},
            ReturnValues="NONE",
        )
        print(f"  ✓ Cleared players for team: {team_name}")
        count += 1
    print(f"Teams updated: {count}")
    return count


def reset_members():
    """Remove assigned attribute for every member item."""
    count = 0
    print(f"Removing 'assigned' attribute from all members in {MEMBERS_TABLE}...")
    for item in scan_all(members_table):
        member_id = item.get("member")
        if not member_id:
            continue
        members_table.update_item(
            Key={"member": member_id},
            UpdateExpression="REMOVE #assigned",
            ExpressionAttributeNames={"#assigned": "assigned"},
            ReturnValues="NONE",
        )
        print(f"  ✓ Cleared assigned for member: {member_id}")
        count += 1
    print(f"Members updated: {count}")
    return count


def clean_questions():
    """Delete all question items where SK starts with 'answer#'."""
    count = 0
    print(f"Deleting all items from {QUESTIONS_TABLE} where SK starts with 'answer#'...")
    for item in scan_all(questions_table):
        pk = item.get("PK")
        sk = item.get("SK")
        if not pk or not sk:
            continue
        if sk.startswith("answer#"):
            questions_table.delete_item(Key={"PK": pk, "SK": sk})
            print(f"  🗑️ Deleted item with PK={pk}, SK={sk}")
            count += 1
    print(f"Questions deleted: {count}")
    return count


def main():
    try:
        teams_updated = reset_teams()
        members_updated = reset_members()
        questions_deleted = clean_questions()

        print("\n✅ Done!")
        print(f"Teams updated: {teams_updated}")
        print(f"Members updated: {members_updated}")
        print(f"Questions deleted: {questions_deleted}")
    except (ClientError, BotoCoreError) as e:
        print(f"❌ ERROR: {e}")


if __name__ == "__main__":
    main()
