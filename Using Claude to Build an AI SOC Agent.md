
| Claude API                                           |
| ---------------------------------------------------- |
| `anthropic` Python SDK (`pip install anthropic`)     |
| `anthropic.Anthropic()` client                       |
| `anthropic.APIError` and its subclasses              |
| Your own `ANTHROPIC_API_KEY`                         |
| `system` parameter, entirely yours                   |
| Structured `tools` param + `tool_use` content blocks |


## Meet the Claude API

Talking to Claude directly means installing Anthropic's own SDK and pointing it at your API key:


```bash
pip install anthropic
export ANTHROPIC_API_KEY="sk-ant-..."
```

The SDK reads `ANTHROPIC_API_KEY` from the environment automatically.

Open `agent_claude.py` 
```python
# After (Claude API)
from anthropic import Anthropic, APIError
```

`Anthropic` sends messages to Claude's `/v1/messages` endpoint; `APIError` (and its subclasses, e.g. `RateLimitError`, `APIConnectionError`) is what you catch when a call fails.


The `system` parameter you send _is_ the complete instruction set and tool-calling isn't a JSON convention you parse out of message text; it's a first-class part of the API. You declare tools with a `name`, `description`, and JSON-schema `input_schema` in a `tools` list, and when Claude wants to use one, it returns a structured `tool_use` content block rather than JSON embedded in prose:

```json
{
  "type": "tool_use",
  "id": "toolu_01A2...",
  "name": "get_alert",
  "input": {
    "alert_id": "ALT-051"
  }
}
```

You won't pass `tools` yet in this first version , that comes once you wire up real capabilities.

## Create the Claude Client

```python
client = Anthropic()
```

The client now has everything it needs (your API key, from the environment) to talk to Claude. It still doesn't know what kind of agent it should behave as  that's next.

## Define the Agent's Role

This part carries over almost unchanged conceptually — the model still needs a role, permitted evidence, a controlled verdict vocabulary, and explicit limits on authority. What changes is _where_ those instructions live: instead of being concatenated into the user's message text (to sit alongside a platform system prompt you don't own), they become the API's own `system` parameter.

```python
AGENT_INSTRUCTIONS = (
    "You are the Security Investigation Agent for NorthStar Fashion, a SOC "
    "assistant. Analyse only the alert and evidence supplied in this "
    "conversation - never invent SIEM data. "
    "Use only these verdicts: TruePositive, BenignPositive, FalsePositive, "
    "or InsufficientEvidence. Respond with a Verdict, Key Evidence, a "
    "one-sentence Reason, and a Recommendation. "
    "You cannot close alerts, change SIEM state, perform containment, block "
    "IP addresses, disable accounts, or run commands - you only support the "
    "human investigation."
)
```

Same rules as before: four controlled verdicts, no containment authority, no invented evidence. The only difference is this string is about to be passed as `system=...`, not glued onto the user turn.

## Send an Investigation Request

```python
investigation_request = "Investigate alert ALT-051."
```

`ALT-051` is still just a string at this point  nothing has retrieved the actual alert yet.

```python
response = client.messages.create(
    model="claude-sonnet-5",
    max_tokens=1024,
    system=AGENT_INSTRUCTIONS,
    messages=[
        {"role": "user", "content": investigation_request}
    ],
)
```

`model` and `max_tokens` are required, explicit arguments.

The response's text lives in `response.content`, a list of content blocks. For a plain text reply (no tool use yet), read it as:

```python
print(response.content[0].text)
```

## Run Your First Agent


```bash
python3 agent_claude.py
```

The application sends `AGENT_INSTRUCTIONS` and `investigation_request` to Claude, but nothing has connected the agent to a SIEM, log source, IP reputation feed, or organisational context yet. Claude recognises `ALT-051` as an alert identifier and understands it's being asked to investigate, but it has no evidence to analyse so, held to the verdict rules in `AGENT_INSTRUCTIONS`, it should return `InsufficientEvidence` rather than invent findings.

**Reasoning about a capability does not grant access to that capability.** Claude may understand what investigating suspicious authentication activity involves, but the application still hasn't given it any way to reach real data.

The next step is to define `list_alerts` and `get_alert` as entries in a `tools` list, check `response.stop_reason == "tool_use"`, execute the matching Python function against your real SIEM data, and send the result back as a `tool_result` content block so Claude can use it before answering.

# Part 2: Give the Agent Real Capabilities

The previous version only ever produced `InsufficientEvidence`, because nothing connected it to the SIEM. This part wires up `list_alerts()` and `get_alert()` as real tools Claude can call.

| Claude API                                                                                         |
| -------------------------------------------------------------------------------------------------- |
| `client.messages.create(messages=...)` is stateless , you resend the whole conversation every call |
| Model told via the `tools` parameter; it returns a structured `tool_use` content block             |
| `response.content` blocks are already typed (`text` vs `tool_use`)                                 |
| A `tool_result` content block, keyed to the call by `tool_use_id`                                  |
| `response.content` can hold several `tool_use` blocks at once (parallel calls)                     |

## Imports and the SIEM Functions Stay Almost Identical

```python
import json
import os

import requests

from anthropic import Anthropic, APIError
```

`list_alerts()` and `get_alert()` are plain functions hitting your SIEM backend and have nothing to do with which model provider is asking for them. 

```python
def get_alert(alert_id: str) -> dict:
    """Retrieve a security alert by its ID, for example ALT-006."""
    response = requests.get(
        f"http://127.0.0.1:8000/services/siem/alerts/{alert_id}",
        headers={"X-SIEM-API-Key": siem_api_key},
        timeout=5,
    )
    response.raise_for_status()
    return response.json()
```

## Declare the Capabilities as Tools
You declare each capability as a JSON Schema entry in a `tools` list:
```python
TOOLS = [
    {
        "name": "list_alerts",
        "description": (
            "List security alerts in small pages. Use to browse or discover "
            "alert IDs before investigating one in detail."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "count": {
                    "type": "integer",
                    "description": "Number of alerts to return per page.",
                },
                "offset": {
                    "type": "integer",
                    "description": "Number of alerts to skip, for pagination.",
                },
            },
        },
    },
    {
        "name": "get_alert",
        "description": "Retrieve full details for a single security alert by its ID, e.g. ALT-006.",
        "input_schema": {
            "type": "object",
            "properties": {
                "alert_id": {
                    "type": "string",
                    "description": "The alert identifier, e.g. ALT-051.",
                },
            },
            "required": ["alert_id"],
        },
    },
]
```

`APPROVED_CAPABILITIES` keeps doing exactly the job it did before: it's the runtime allow-list Claude's requested tool name is checked against before anything actually executes. That defense-in-depth idea doesn't change just because the calling convention did:

```python
APPROVED_CAPABILITIES = {
    "list_alerts": list_alerts,
    "get_alert": get_alert,
}
```

## `run_tool_call()` 

Same logic, just fed from a `tool_use` block's `.name` / `.input` instead of a hand-parsed dict:

```python
def run_tool_call(name: str, arguments: dict):
    """Execute an approved capability requested by Claude and return its
    result as evidence - never as a new instruction."""
    capability = APPROVED_CAPABILITIES.get(name)
    if capability is None:
        return {"error": f"'{name}' is not an approved capability yet."}

    print(f"  - {name}")
    try:
        return capability(**arguments)
    except requests.RequestException as error:
        return {"error": f"{name} failed: {error}"}
    except TypeError as error:
        return {"error": f"{name} was called with bad arguments: {error}"}
```

## The Investigation Loop

The Claude Messages API is **stateless**: every call must carry the _entire_ conversation so far, including the assistant's previous turn (tool calls and all) and the tool results you're feeding back. So instead of reassigning a single `message` string each loop iteration, you grow a `messages` list.

```python
MAX_TOOL_CALLS_PER_TURN = 5

def investigate(user_message: str) -> str:
    """Relay the user's message to Claude, fulfilling one approved
    tool_use at a time, until Claude gives a final, human-readable
    answer instead of another tool request."""
    messages = [{"role": "user", "content": user_message}]
    print("\nInvestigation steps:")

    for _ in range(MAX_TOOL_CALLS_PER_TURN):
        response = client.messages.create(
            model="claude-sonnet-5",
            max_tokens=1024,
            system=AGENT_INSTRUCTIONS,
            tools=TOOLS,
            messages=messages,
        )

        if response.stop_reason != "tool_use":
            return "".join(
                block.text for block in response.content if block.type == "text"
            )

        # Claude's own turn - including its tool_use blocks - has to be
        # replayed back to it on the next call, since the API is stateless.
        messages.append({"role": "assistant", "content": response.content})

        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            result = run_tool_call(block.name, block.input)
            tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": json.dumps(result),
                }
            )

        messages.append({"role": "user", "content": tool_results})

    return "Investigation stopped after too many tool requests without a final answer."
```

Two things worth noticing:

- `response.content` can contain **several** `tool_use` blocks in a single response if Claude decides to, say, call `list_alerts` and `get_alert` together. The loop above already handles that for free, since it collects every `tool_use` block's result into one `tool_result`-bearing user turn before calling Claude again.
- `tool_result` content is expected to be a string, so SIEM results (Python dicts) are serialised with `json.dumps()` — the direct equivalent of the original's `"TOOL_RESULT: " + json.dumps(result)`, minus the hand-rolled prefix, since the API already knows this block is a tool result from its `type`.

## Wiring It Up

```python
client = Anthropic()

print("Security Investigation Agent ready. Try: Investigate alert ALT-051.")

while True:
    human_msg = input("\nUser: ")

    try:
        answer = investigate(human_msg)
    except APIError as error:
        print(f"AI request failed: {error}")
        continue

    print("\nAssistant:")
    print(answer)
    print("\n" + "-" * 60)
```

Run it, ask it to investigate `ALT-051` again, and this time with `get_alert` declared as a real tool , Claude has something to call before it answers, instead of only being able to say `InsufficientEvidence`.

### Full Code
```python
"""  
NorthStar Fashion Security Investigation Agent - Claude API version.  
  
Setup:  
pip install anthropic requests  
export ANTHROPIC_API_KEY="sk-ant-..."  
export SIEM_API_KEY="..." # optional, falls back to the demo key below  
  
Run:  
python3 agent_claude.py  
> Investigate alert ALT-051.  
"""  
  
import json  
import os  
  
import requests  
  
from anthropic import Anthropic, APIError  
  
MODEL = "claude-sonnet-5"  
MAX_TOOL_CALLS_PER_TURN = 8  
  
# A design choice, not an API-enforced limit - Claude's own context window is  
# far larger than this. But large, unfocused log dumps still cost tokens,  
# latency, and reasoning quality, so tool results are still capped and  
# trimmed before being sent back, the same engineering principle the lab's  
# 4096-character TOOL_RESULT: <json> limit was demonstrating.  
MAX_TOOL_RESULT_CHARS = 20000  
  
# Load the SIEM API key. Falls back to the fixed demo key baked into  
# SIEM/SIEM/backend/server.py's API_KEYS (not a secret) so the agent still  
# works even when SIEM_API_KEY hasn't reached this session yet.  
siem_api_key = os.getenv("SIEM_API_KEY", "sk_live_demo_9f3a21c4b77d4d3e")  
  
  
# --------------------------------------------------------------------------  
# SIEM capabilities - plain functions, unrelated to which model calls them  
# --------------------------------------------------------------------------  
  
def list_alerts(count: int = 10, offset: int = 0) -> list:  
"""List security alerts in small pages."""  
response = requests.get(  
"http://127.0.0.1:8000/services/siem/alerts",  
headers={"X-SIEM-API-Key": siem_api_key},  
params={"count": count, "offset": offset},  
timeout=5,  
)  
response.raise_for_status()  
data = response.json()  
  
return [  
{  
"id": alert["id"],  
"name": alert["name"],  
"severity": alert["severity"],  
"status": alert["status"],  
}  
for alert in data["value"]  
]  
  
  
def get_alert(alert_id: str) -> dict:  
"""Retrieve a security alert by its ID, for example ALT-006."""  
response = requests.get(  
f"http://127.0.0.1:8000/services/siem/alerts/{alert_id}",  
headers={"X-SIEM-API-Key": siem_api_key},  
timeout=5,  
)  
response.raise_for_status()  
return response.json()  
  
  
# Fields that exist for transport, storage, or indexing rather than  
# investigation - stripped before evidence reaches the model so it doesn't  
# spend context on noise like raw_log duplicating the normalised event.  
FIELDS_TO_SKIP = {  
"schema_version",  
"receive_timestamp",  
"source_format",  
"customer_id",  
"organization_id",  
"log_name",  
"log_type",  
"raw_log",  
}  
  
  
def remove_empty_fields(value):  
"""Recursively drop noisy/transport fields and empty values (None,  
'', [], {}) from a log event, without enforcing a fixed schema - useful  
fields stay available whatever the event type."""  
if isinstance(value, dict):  
cleaned = {}  
for key, val in value.items():  
if key in FIELDS_TO_SKIP:  
continue  
cleaned_val = remove_empty_fields(val)  
if cleaned_val in (None, "", [], {}):  
continue  
cleaned[key] = cleaned_val  
return cleaned  
if isinstance(value, list):  
cleaned_list = [remove_empty_fields(item) for item in value]  
return [item for item in cleaned_list if item not in (None, "", [], {})]  
return value  
  
  
def search_logs(query: str, count: int = 10, offset: int = 0) -> dict:  
"""Search normalised SIEM logs with a query expression, paginated."""  
response = requests.post(  
"http://127.0.0.1:8000/services/siem/search",  
headers={"X-SIEM-API-Key": siem_api_key},  
json={  
"search": query,  
"count": count,  
"offset": offset,  
},  
timeout=5,  
)  
response.raise_for_status()  
data = response.json()  
  
results = [remove_empty_fields(event) for event in data["results"]]  
  
return {  
"total": data["totalResultCount"],  
"count": len(results),  
"offset": data["offset"],  
"truncated": data["truncated"],  
"results": results,  
}  
  
  
def build_tool_result_content(result) -> str:  
"""Serialise a tool result for Claude, trimming it to stay within a  
sane size budget. Log-heavy tools like search_logs can return more  
evidence than is useful in one turn, so if the serialised result is too  
large, entries are progressively dropped from a "results" list and the  
response is marked truncated_for_message_limit. If it still doesn't fit  
with no results left, a short error asks for a more focused search."""  
payload = json.dumps(result)  
if len(payload) <= MAX_TOOL_RESULT_CHARS:  
return payload  
  
if isinstance(result, dict) and isinstance(result.get("results"), list):  
trimmed = dict(result)  
while trimmed["results"] and len(json.dumps(trimmed)) > MAX_TOOL_RESULT_CHARS:  
trimmed["results"] = trimmed["results"][:-1]  
trimmed["count"] = len(trimmed["results"])  
trimmed["truncated_for_message_limit"] = True  
payload = json.dumps(trimmed)  
if len(payload) <= MAX_TOOL_RESULT_CHARS:  
return payload  
  
return json.dumps(  
{  
"error": (  
"Result too large even after trimming - narrow the search "  
"query, reduce count, or add more specific filters."  
)  
}  
)  
  
  
# --------------------------------------------------------------------------  
# Agent role and the tools Claude is allowed to ask for  
# --------------------------------------------------------------------------  
  
AGENT_INSTRUCTIONS = (  
"You are the Security Investigation Agent for NorthStar Fashion, a SOC "  
"assistant. Analyse only the alert and evidence supplied in this "  
"conversation - never invent SIEM data. "  
"Use only these verdicts: TruePositive, BenignPositive, FalsePositive, "  
"or InsufficientEvidence. Respond with a Verdict, Key Evidence, a "  
"one-sentence Reason, and a Recommendation. "  
"You cannot close alerts, change SIEM state, perform containment, block "  
"IP addresses, disable accounts, or run commands - you only support the "  
"human investigation. "  
"Investigate efficiently: call get_alert first. Only call search_logs "  
"for evidence that directly supports or refutes a verdict for THIS "  
"alert - for example the same user, IP, host, or a tight time window "  
"around it. Never repeat a search you've already run, and never search "  
"speculatively. As soon as you have enough evidence to reach one of the "  
"four verdicts, stop calling tools and answer - exhaustive coverage of "  
"every related log is not the goal."  
)  
  
TOOLS = [  
{  
"name": "list_alerts",  
"description": (  
"List security alerts in small pages. Use to browse or discover "  
"alert IDs before investigating one in detail."  
),  
"input_schema": {  
"type": "object",  
"properties": {  
"count": {  
"type": "integer",  
"description": "Number of alerts to return per page.",  
},  
"offset": {  
"type": "integer",  
"description": "Number of alerts to skip, for pagination.",  
},  
},  
},  
},  
{  
"name": "get_alert",  
"description": "Retrieve full details for a single security alert by its ID, e.g. ALT-006.",  
"input_schema": {  
"type": "object",  
"properties": {  
"alert_id": {  
"type": "string",  
"description": "The alert identifier, e.g. ALT-051.",  
},  
},  
"required": ["alert_id"],  
},  
},  
{  
"name": "search_logs",  
"description": (  
"Search normalised SIEM logs with a query expression. Returns a "  
"page of matching, cleaned log events plus pagination state "  
"(total, count, offset, truncated). Use to gather supporting "  
"evidence beyond a single alert - for example, related sign-in "  
"or device activity for the same user or IP. If truncated is "  
"true, request the next page by increasing offset."  
),  
"input_schema": {  
"type": "object",  
"properties": {  
"query": {  
"type": "string",  
"description": "SIEM search expression, e.g. user:alice AND event_type:signin.",  
},  
"count": {  
"type": "integer",  
"description": "Number of log events to return per page.",  
},  
"offset": {  
"type": "integer",  
"description": "Number of matching events to skip, for pagination.",  
},  
},  
"required": ["query"],  
},  
},  
]  
  
# The only capabilities Claude can ever trigger. Its requested tool name is  
# checked against this list before anything runs - an unapproved or unknown  
# name is refused here, not executed.  
APPROVED_CAPABILITIES = {  
"list_alerts": list_alerts,  
"get_alert": get_alert,  
"search_logs": search_logs,  
}  
  
  
def run_tool_call(name: str, arguments: dict):  
"""Execute an approved capability requested by Claude and return its  
result as evidence - never as a new instruction."""  
capability = APPROVED_CAPABILITIES.get(name)  
if capability is None:  
return {"error": f"'{name}' is not an approved capability yet."}  
  
print(f" - {name}({arguments})")  
try:  
return capability(**arguments)  
except requests.RequestException as error:  
return {"error": f"{name} failed: {error}"}  
except TypeError as error:  
return {"error": f"{name} was called with bad arguments: {error}"}  
  
  
# --------------------------------------------------------------------------  
# Investigation loop  
# --------------------------------------------------------------------------  
  
client = Anthropic()  
  
  
def extract_text(response) -> str:  
text = "".join(block.text for block in response.content if block.type == "text")  
return text or "(no answer text returned)"  
  
  
def investigate(user_message: str) -> str:  
"""Relay the user's message to Claude, fulfilling one approved  
tool_use at a time, until Claude gives a final, human-readable  
answer instead of another tool request."""  
messages = [{"role": "user", "content": user_message}]  
print("\nInvestigation steps:")  
  
for _ in range(MAX_TOOL_CALLS_PER_TURN):  
response = client.messages.create(  
model=MODEL,  
max_tokens=1024,  
system=AGENT_INSTRUCTIONS,  
tools=TOOLS,  
messages=messages,  
)  
  
if response.stop_reason != "tool_use":  
return extract_text(response)  
  
# Claude's own turn - including its tool_use blocks - has to be  
# replayed back to it on the next call, since the API is stateless.  
messages.append({"role": "assistant", "content": response.content})  
  
tool_results = []  
for block in response.content:  
if block.type != "tool_use":  
continue  
result = run_tool_call(block.name, block.input)  
tool_results.append(  
{  
"type": "tool_result",  
"tool_use_id": block.id,  
"content": build_tool_result_content(result),  
}  
)  
  
messages.append({"role": "user", "content": tool_results})  
  
# Tool budget exhausted - force a real answer from whatever evidence  
# was already gathered, instead of returning nothing useful. Omitting  
# `tools` here means Claude has nothing left to call - it must reply  
# with text.  
messages.append(  
{  
"role": "user",  
"content": (  
"You've reached the tool call limit for this investigation. "  
"Give your best Verdict, Key Evidence, Reason, and "  
"Recommendation using only the evidence already gathered "  
"above. If that's not enough, answer InsufficientEvidence."  
),  
}  
)  
response = client.messages.create(  
model=MODEL,  
max_tokens=1024,  
system=AGENT_INSTRUCTIONS,  
messages=messages,  
)  
return extract_text(response)  
  
  
# --------------------------------------------------------------------------  
# Make it interactive  
# --------------------------------------------------------------------------  
  
def main():  
print("Security Investigation Agent ready. Try: Investigate alert ALT-051.")  
  
while True:  
try:  
human_msg = input("\nUser: ")  
except (EOFError, KeyboardInterrupt):  
print()  
break  
  
try:  
answer = investigate(human_msg)  
except APIError as error:  
print(f"AI request failed: {error}")  
continue  
  
print("\nAssistant:")  
print(answer)  
print("\n" + "-" * 60)  
  
  
if __name__ == "__main__":  
main()
```