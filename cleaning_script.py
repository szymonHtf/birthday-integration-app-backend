#!/usr/bin/env python3
import boto3
from botocore.exceptions import BotoCoreError, ClientError

# --- CONFIGURATION ---
REGION = "eu-central-1"
TEAMS_TABLE = "birthday-integration-app-teams"
MEMBERS_TABLE = "birthday-integration-app-members"
# ----------------------

session = boto3.Session(region_name=REGION)
dynamodb = session.resource("dynamodb")

teams_table = dynamodb.Table(TEAMS_TABLE)
members_table = dynamodb.Table(MEMBERS_TABLE)


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


def main():
    try:
        teams_updated = reset_teams()
        members_updated = reset_members()
        print("\n✅ Done!")
        print(f"Teams updated: {teams_updated}")
        print(f"Members updated: {members_updated}")
    except (ClientError, BotoCoreError) as e:
        print(f"❌ ERROR: {e}")


if __name__ == "__main__":
    main()
