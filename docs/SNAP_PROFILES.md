# SNAP Profiles

SNAP is an opt-in path planner. Without a selected profile, SHPH keeps its
existing direct-TCP connection behavior. Select a profile in `[session]` with
`snap_profile = "path/to/profile.json"` or pass `--snap-profile path/to/profile`
to `shph up`; the command-line value takes precedence.

Profiles use version 1 and can be JSON or TOML. Parsing is strict: unknown
fields, unsupported versions, and duplicate object keys are rejected. A set
`shuffle_seed` also produces the same retry-round ordering as Python's SNAP
reference. Use `shph snap validate <file>` to check the profile and
`shph snap plan <file>` to resolve its peer against the local keystore and
print the deterministic candidate plan.

At runtime, a candidate timeout is capped by the remaining `max_elapsed_sec`.
Bridge setup and the SHPH handshake share one absolute candidate deadline, and
the runtime will not start another candidate with less than 200 ms remaining.

## Audit records

Runtime records use schema version 1 and a shared correlation ID for one
candidate-attempt sequence. They include the profile name and hash, a hashed
reference to the locally pinned peer, a plan ID, candidate ID and source,
adapter and path type, round and attempt numbers, the effective timeout when
an attempt starts, elapsed time, result, and a normalized failure reason. The
records omit raw endpoints, profile and key-file paths, relay key material,
and transport error text. The peer reference and plan ID support correlation
without exposing the pinned fingerprint or candidate endpoints. Candidate IDs
use Python SNAP's shared candidate fields; SHPH-only service-contract metadata
is excluded from those IDs.

## External service declaration

Every network bridge or relay must include `operator_service_contract` before
CLI validation, planning, or session use. The declaration has three required
text fields:

- `owner`: the person or organization operating the service.
- `service_id`: an operator-chosen identifier for the service.
- `authorization_ref`: an operator-chosen reference to the authorization or
  ownership record.

This is self-attested metadata. SHPH checks that the fields are present and
well-formed; it does not verify ownership or authorization independently.
Local `mesh-dtn-local` and `mule-usb` adapters do not use this declaration.

Example JSON profile:

```json
{
  "version": 1,
  "profile_name": "lab-paths",
  "peer_alias": "peer1",
  "direct_endpoints": [
    { "ip": "192.0.2.10", "port": 443 }
  ],
  "bridges": [
    {
      "label": "owned-relay",
      "ip": "192.0.2.20",
      "port": 9443,
      "key_file": "relay.key",
      "operator_service_contract": {
        "owner": "Example Operations",
        "service_id": "lab-relay-1",
        "authorization_ref": "change-record-1234"
      }
    }
  ]
}
```

Adapter availability and evidence limits are recorded in
[`SUPPORT_MATRIX.md`](SUPPORT_MATRIX.md). A valid plan does not establish
adapter interoperability or host-level release acceptance.
