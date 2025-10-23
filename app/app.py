import json
import os
from enum import StrEnum
from typing import Optional, Union, Dict, Any

import boto3
from aws_lambda_powertools import Logger
from aws_lambda_powertools import Metrics
from aws_lambda_powertools import Tracer
from aws_lambda_powertools.event_handler import APIGatewayRestResolver, Response
from aws_lambda_powertools.logging import correlation_paths
from aws_lambda_powertools.metrics import MetricUnit
from aws_lambda_powertools.utilities.typing import LambdaContext
from botocore.exceptions import ClientError

# ---- CORS helper (put near the top of the file) ----
CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
}


def cors_json(status_code: int = 200, body: Optional[Union[dict, list, str]] = None) -> Response:
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
    DEMENTORS = "Dementorzy"
    SOULS = "Duszyczki"
    ZOMBIES = "Zombiaki"
    GOSSIPS = "Plotkary"
    GOACIKS = "Goaciki"
    CURSED = "Przeklęci"
    CORPSES = "Truposze"


class AnswerType(StrEnum):
    QUESTION_ONLY = "QUESTION_ONLY",
    USER_ANSWER = "USER_ANSWER",
    CORRECT_ANSWER = "CORRECT_ANSWER",


# Helper: choose a random valid team value (unique by value)
TEAM_VALUES = sorted({t.value for t in Team})

MEMBER_TO_TEAM = {
    "Łukasz": Team.DEMENTORS.value,
    "Gaba": Team.DEMENTORS.value,
    "Natalia": Team.SOULS.value,
    "Zuza": Team.SOULS.value,
    "Eryk": Team.ZOMBIES.value,
    "Hubert N": Team.ZOMBIES.value,
    "Julita": Team.GOSSIPS.value,
    "Monika": Team.GOSSIPS.value,
    "Adam": Team.GOACIKS.value,
    "Paweł": Team.GOACIKS.value,
    "Oskar": Team.CURSED.value,
    "Mati": Team.CURSED.value,
    "Hubert Cz": Team.CORPSES.value,
    "Paula": Team.CORPSES.value,
}


def _pick_random_team(member: str) -> str:
    """
    Returns the canonical team id (e.g. 'dementors').
    Raises ValueError for unknown members.
    """
    team = MEMBER_TO_TEAM.get(member)
    if not team:
        raise ValueError(f"Unknown member: {member}")
    return team


dynamodb = boto3.resource("dynamodb")
dynamodb_client = boto3.client("dynamodb")

TEAMS_TABLE = os.environ["TEAMS_TABLE_NAME"]
MEMBERS_TABLE = os.environ["MEMBERS_TABLE_NAME"]
QUESTIONS_TABLE = os.environ["QUESTIONS_TABLE_NAME"]

teams_table = dynamodb.Table(TEAMS_TABLE)
members_table = dynamodb.Table(MEMBERS_TABLE)
questions_table = dynamodb.Table(QUESTIONS_TABLE)


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


def _get_state():
    resp = questions_table.get_item(Key={"PK": "STATE", "SK": "STATE"})
    item = resp.get("Item")
    if not item:
        return None
    return item.get("question_number")


def _get_question(teammate, number):
    resp = questions_table.get_item(Key={"PK": teammate.upper(), "SK": f"question#{number}"})
    item = resp.get("Item")
    if not item:
        return None
    return {
        "question": item.get("question"),
        "question_number": number,
        "answer1": item.get("answer1"),
        "answer2": item.get("answer2"),
        "answer3": item.get("answer3"),
        "answer4": item.get("answer4"),
    }


def _validate(body: Dict[str, Any]):
    required = [
        "member",
        "team",
        "teammate",
        "question_number",
        "answer_index",
        "answer_text",
    ]
    missing = [k for k in required if k not in body]
    if missing:
        return False, {"error": "missing_fields", "fields": missing}

    try:
        qnum = int(body["question_number"])
        aidx = int(body["answer_index"])
    except Exception:
        return False, {"error": "invalid_types", "details": "question_number and answer_index must be integers"}

    if not (1 <= aidx <= 4):
        return False, {"error": "invalid_answer_index", "details": "answer_index must be 1..4"}

    if not isinstance(body["member"], str) or not body["member"].strip():
        return False, {"error": "invalid_member"}
    if not isinstance(body["team"], str) or not body["team"].strip():
        return False, {"error": "invalid_team"}
    if not isinstance(body["teammate"], str) or not body["teammate"].strip():
        return False, {"error": "invalid_teammate"}
    if not isinstance(body["answer_text"], str) or not body["answer_text"].strip():
        return False, {"error": "invalid_answer_text"}

    return True, None


@app.get("/teams")
@tracer.capture_method
def get_teams():
    items = _scan_all(teams_table)

    valid_values = {t.value for t in Team}
    teams = [i for i in items if i.get("team_name") in valid_values]

    order = {t.value: idx for idx, t in enumerate(Team)}
    teams.sort(key=lambda x: order.get(x.get("team_name", ""), 10 ** 9))

    return cors_json(200, {"teams": teams})


@app.get("/question")
@tracer.capture_method
def get_question():
    number = _get_state()
    logger.info(f"Question number {number}")
    logger.info(f"number is instanceof {type(number)}")
    number_str = str(number)
    if number_str == "0":
        return cors_json(409)
    else:
        teammate = app.current_event.get_query_string_value("teammate")
        logger.info(f"teammate: {teammate}")
        question = _get_question(teammate, number_str)
        return cors_json(200, question)


@app.get("/answer")
@tracer.capture_method
def get_question():
    number = _get_state()
    if number == "0":
        return cors_json(409)
    else:
        teammate = app.current_event.get_query_string_value("teammate")
        type_str = app.current_event.get_query_string_value("type")
        if not type_str:
            raise ValueError("Missing required query parameter: 'type'")
        type: AnswerType = AnswerType(type_str)
        question_number = app.current_event.get_query_string_value("question_number")
        answerer = app.current_event.get_query_string_value("member")

        question = _get_question(teammate, number)
        return cors_json(200, question)


@app.get("/unassigned-member")
@tracer.capture_method
def get_unassigned_member():
    return cors_json(200, {"unassigned_member": _get_first_unassigned_member()})


@app.post("/code")
@tracer.capture_method
def code():
    body = app.current_event.json_body or {}
    code = body.get("code")

    if not code or not isinstance(code, str):
        return cors_json(400, {"error": "Code is not string"})

    members = _scan_all(members_table)

    for member in members:
        if member.get("code") == code:
            teams = _scan_all(teams_table)
            for team in teams:
                players = team.get("players", [])
                if member.get("member") in players:
                    teammate = next((p for p in players if p != member.get("member")), None)
                    member["teammate"] = teammate
            return cors_json(200, {"data": member})
    return cors_json(400, {"error": "Invalid code"})


@app.post("/answer")
@tracer.capture_method
def code():
    body = app.current_event.json_body or {}

    ok, err = _validate(body)
    if not ok:
        logger.warning("Validation failed", extra={"error": err, "body": body})
        return cors_json(400, err)

    payload = {
        "who_answered": str(body["member"]).strip(),
        "team": str(body["team"]).strip(),
        "teammate": str(body["teammate"]).strip(),
        "question_number": int(body["question_number"]),
        "answer_index": int(body["answer_index"]),
        "answer_text": str(body["answer_text"]).strip(),
    }

    try:
        questions_table.put_item(
            Item={
                "PK": payload["teammate"].upper(),
                "SK": f"answer#{payload['question_number']}",
                "who_answered": payload["who_answered"],
                "team": payload["team"],
                "teammate": payload["teammate"],
                "question_number": payload["question_number"],
                "answer_index": payload["answer_index"],
                "answer_text": payload["answer_text"],
            }
        )
        logger.info("Answer stored", extra={"payload": payload})
        return cors_json(200, {"status": "ok"})
    except Exception as e:
        logger.exception("Failed to update item")
        return cors_json(500, {"error": str(e)})


@app.post("/assign")
@tracer.capture_method
def assign_member():
    body = app.current_event.json_body or {}
    member = body.get("member")

    if not member or not isinstance(member, str):
        return cors_json(400, {"message": "member is required (string)"})
    logger.info("assigning member %s", member)
    try:
        team = _pick_random_team(member)
    except ValueError as e:
        return cors_json(400, {"message": str(e)})
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
        members_table.update_item(
            Key={"member": member},
            UpdateExpression="SET #a = :team",
            ExpressionAttributeNames={"#a": "assigned"},
            ExpressionAttributeValues={":team": team},
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
