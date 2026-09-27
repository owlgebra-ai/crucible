# Live Vultr account attestation

Run this from the trusted local checkout immediately before a judge walkthrough:

```sh
CRUCIBLE_MANAGEMENT_KEY_FILE=secrets/YOUR_MANAGEMENT_KEY.json \
  python3 -m deploy.judge_attestation
```

The command reads the three owner-only recovery records in `secrets/` and the
owner-only local `.env.local` file. With the Vultr management credential, it
uses **GET requests only** to inspect the two VM instances, their saved VPC,
and the account's Serverless Inference subscriptions. It confirms both VMs
are distinct, `active`/`ok`/`running`, in `sjc`, and attached to the same live
VPC. It also confirms that the local inference credential matches exactly one
active subscription returned by that same Vultr account. Vultr documents the
[subscription list and detail API](https://docs.vultr.com/products/compute/serverless-inference/management/health-checks).

Success prints one JSON object with `attested: true`, a UTC check time,
bounded VM statuses, `region: "sjc"`, `shared_vpc: true`, the count of active
inference subscriptions, and
`inference_key_matches_account_subscription: true`. It prints no API
response, key, key hash, resource ID, IP address, subscription label, or
account metadata. Any missing resource, malformed response, mismatch, or
unavailable API makes the command exit **2** with only
`{"attested": false, "reason": "verification_failed", ...}`.

This is an account and live-resource check. It does not execute a model call,
verify the inference credential installed on the control VM, or prove sandbox
containment. In the live walkthrough, pair it with the control VM's authenticated
`python3 -m crucible.vultr smoke --chat`, the private trajectory pane, and the
separate disposable-worker boundary proof. The model weights are
Vultr-hosted; the subscription credential belongs to the operator's Vultr
account.
