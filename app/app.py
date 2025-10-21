import json
import os
import random
from enum import StrEnum

import boto3
from aws_lambda_powertools.event_handler import APIGatewayRestResolver, Response
from aws_lambda_powertools.utilities.typing import LambdaContext
from aws_lambda_powertools.logging import correlation_paths
from aws_lambda_powertools import Logger
from aws_lambda_powertools import Tracer
from aws_lambda_powertools import Metrics
from aws_lambda_powertools.metrics import MetricUnit
from botocore.exceptions import ClientError
from numpy.f2py.auxfuncs import throw_error

# ---- CORS helper (put near the top of the file) ----
CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
}

def cors_json(status_code: int = 200, body: dict | list | str | None = None) -> Response:
    if body is None:
        payload = ""
    elif isinstance(body, str):
        payload = body
    else:
        payload = json.dumps(body)
    return Response(
        status_code=status_code,
        headers=CORS_HEADERS,
        content_type="application/json",
        body=payload,
    )

app = APIGatewayRestResolver()
tracer = Tracer()
logger = Logger()
metrics = Metrics(namespace="Powertools")


class Team(StrEnum):
    RED = "CZERWONI"
    BLUE = "NIEBIESCY"
    GREEN = "ZIELONI"
    PURPLE = "FIOLETOWI"
    BLACK = "CZARNI"
    ORANGE = "POMARAŃCZOWI"
    YELLOW = "ŻÓŁCI"


# Helper: choose a random valid team value (unique by value)
TEAM_VALUES = sorted({t.value for t in Team})


def _pick_random_team(member: str) -> str:
    if member is "Łukasz":
        return Team.RED
    if member is "Gaba":
        return Team.RED
    if member is "Natalia":
        return Team.BLUE
    if member is "Zuza":
        return Team.BLUE
    if member is "Eryk":
        return Team.GREEN
    if member is "Hubert N":
        return Team.GREEN
    if member is "Julita":
        return Team.PURPLE
    if member is "Monika":
        return Team.PURPLE
    if member is "Adam":
        return Team.BLACK
    if member is "Paweł":
        return Team.BLACK
    if member is "Oskar":
        return Team.ORANGE
    if member is "Mati":
        return Team.ORANGE
    if member is "Hubert Cz":
        return Team.YELLOW
    if member is "Paula":
        return Team.YELLOW
    raise ValueError(f"Unknown member: {member}")


dynamodb = boto3.resource("dynamodb")
dynamodb_client = boto3.client("dynamodb")

TEAMS_TABLE = os.environ["TEAMS_TABLE_NAME"]
MEMBERS_TABLE = os.environ["MEMBERS_TABLE_NAME"]

teams_table = dynamodb.Table(TEAMS_TABLE)
members_table = dynamodb.Table(MEMBERS_TABLE)


def _scan_all(table):
    items = []
    start_key = None
    while True:
        kwargs = {}
        if start_key:
            kwargs["ExclusiveStartKey"] = start_key
        resp = table.scan(**kwargs)
        items.extend(resp.get("Items", []))
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break
    return items


def _get_first_unassigned_member():
    for member in _scan_all(members_table):
        if not member.get("assigned"):
            return member
    return None


@app.get("/teams")
@tracer.capture_method
def get_teams():
    items = _scan_all(teams_table)

    valid_values = {t.value for t in Team}
    teams = [i for i in items if i.get("team_name") in valid_values]

    order = {t.value: idx for idx, t in enumerate(Team)}
    teams.sort(key=lambda x: order.get(x.get("team_name", ""), 10 ** 9))

    return cors_json(200, {"teams": teams})


@app.get("/unassigned-member")
@tracer.capture_method
def get_teams():
    return cors_json(200, {"unassigned_member": _get_first_unassigned_member()})


@app.post("/assign")
@tracer.capture_method
def assign_member():
    body = app.current_event.json_body or {}
    member = body.get("member")

    if not member or not isinstance(member, str):
        return cors_json(400, {"message": "member is required (string)"})

    # Pick any team (no balancing/constraints)
    team = _pick_random_team(member)
    logger.info("Random team selected", team=team)

    try:
        # 1) Append to team's players (no conditions, so duplicates are possible)
        teams_table.update_item(
            Key={"team_name": team},
            UpdateExpression="SET #players = list_append(if_not_exists(#players, :empty), :new)",
            ExpressionAttributeNames={"#players": "players"},
            ExpressionAttributeValues={
                ":empty": [],
                ":new": [member],
            },
            ReturnValues="NONE",
        )

        # 2) Write/overwrite the member's assigned team (no condition)
        members_table.put_item(
            Item={
                "member": member,
                "assigned": team,
            }
        )

        metrics.add_metric(name="AssignSuccess", unit=MetricUnit.Count, value=1)
        logger.info("Assignment saved", team=team)
        return cors_json(200, {"member": member, "team": team})

    except ClientError as e:
        logger.error("Assignment failed", error=str(e))
        return cors_json(500, {"message": "Assignment failed"})


# Enrich logging with contextual information from Lambda
@logger.inject_lambda_context(correlation_id_path=correlation_paths.API_GATEWAY_REST)
# Adding tracer
# See: https://awslabs.github.io/aws-lambda-powertools-python/latest/core/tracer/
@tracer.capture_lambda_handler
# ensures metrics are flushed upon request completion/failure and capturing ColdStart metric
@metrics.log_metrics(capture_cold_start_metric=True)
def lambda_handler(event: dict, context: LambdaContext) -> dict:
    return app.resolve(event, context)
