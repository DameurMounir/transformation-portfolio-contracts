# Digest profile: `TPC-JCS-SHA256-v1`

## Normative profile

`TPC-JCS-SHA256-v1` defines one deterministic content-integrity method for every portfolio stage.
It uses:

- UTF-8 JSON constrained to the I-JSON-compatible domain required by RFC 8785;
- RFC 8785 JSON Canonicalization Scheme (JCS);
- SHA-256;
- lowercase, bare 64-character hexadecimal digest strings.

There is no `0x` prefix, algorithm prefix, whitespace, or uppercase form in a stored digest.

## Parsing requirements

Before canonicalization, an implementation must reject:

- duplicate object member names;
- malformed Unicode or values that JCS cannot represent;
- `NaN`, positive or negative infinity, and non-JSON numeric syntax;
- any value that cannot be validated under its pinned contract.

Object-member order and insignificant input whitespace do not affect JCS output. Array order does
affect it. A validator must not pre-normalize business strings, trim content, reorder business
arrays, coerce numbers, or insert defaults before computing a digest.

Define:

```text
JCS(value) = RFC 8785 canonical UTF-8 bytes of value
H(bytes)   = lowercase hexadecimal SHA-256 of bytes
```

## Payload digest

The payload digest binds the stage-specific `payload` object exactly:

```text
payload_sha256 = H(JCS(artifact.payload))
```

It does not include envelope fields. The stored `payload_sha256` must equal the recomputed value
before artifact or lineage verification proceeds.

## Artifact digest

Create the artifact projection by copying the complete top-level artifact object and removing only
these two top-level members:

```text
artifact_sha256
chain_sha256
```

No nested field is removed. In particular, the projection retains:

- `payload_sha256`;
- every input reference and its `sha256` and `chain_sha256`;
- producer provenance, authority, lifecycle, limitations, and supersession;
- the complete stage payload.

Then compute:

```text
artifact_sha256 = H(JCS(artifact_projection))
```

Removing only the two top-level digest fields avoids a self-reference while binding every other
portable assertion. Implementations must not recursively remove fields with the same names.

## Chain digest

Construct this exact JSON value:

```json
{
  "digest_profile": "TPC-JCS-SHA256-v1",
  "artifact_id": "<current artifact ID>",
  "artifact_sha256": "<verified current artifact digest>",
  "inputs": [
    {
      "artifact_id": "<upstream artifact ID>",
      "artifact_sha256": "<verified upstream artifact digest>",
      "chain_sha256": "<verified upstream chain digest>",
      "relationship": "<declared relationship>"
    }
  ]
}
```

Sort the `inputs` array lexically by this tuple before canonicalization:

```text
(artifact_id, relationship, artifact_sha256)
```

The envelope's upstream reference field is named `sha256`. When building chain material, the
verified value is copied without transformation into the explicit `artifact_sha256` member shown
above. This distinguishes the normalized chain projection from the transport reference while
preserving the same digest value.

The root artifact uses an empty `inputs` array. Compute:

```text
chain_sha256 = H(JCS(chain_material))
```

The literal `digest_profile` value provides algorithm-domain separation. This v1 profile adds no
other separator. Changing the projection, fields, input ordering, canonicalizer, or hash algorithm
requires a new digest profile and normally a new contract major.

## Verification algorithm

For an ordered or unordered set of artifacts, a verifier must:

1. parse every document without ambiguity and validate its schema;
2. ensure one artifact ID maps to exactly one artifact digest;
3. recompute and compare every payload digest;
4. recompute and compare every artifact digest;
5. resolve every declared input by both artifact ID and expected digest;
6. verify compatible identity, lifecycle, producer, authority, and chronology rules;
7. detect cycles in the input graph;
8. process roots before descendants and recompute every chain digest;
9. compare stored and recomputed chain digests using a constant-time equality operation where the
   implementation exposes one;
10. reject the entire requested chain if any check fails.

The verifier does not repair a digest, skip an unavailable input, or downgrade a mismatch to a
warning.

## Minimal canonicalization vector

For this JSON value:

```json
{
  "b": "x",
  "a": 1
}
```

The JCS UTF-8 bytes, shown as text, are:

```text
{"a":1,"b":"x"}
```

Their SHA-256 is:

```text
ecf9e98ec0641e23113ff3ce8bdc78d0ddd249886517fd4a7f68cc83d4e65667
```

For a root chain material object with artifact ID `A-001` and an artifact digest consisting of 64
lowercase `a` characters, the canonical text is:

```text
{"artifact_id":"A-001","artifact_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","digest_profile":"TPC-JCS-SHA256-v1","inputs":[]}
```

The resulting chain SHA-256 is:

```text
44a11d9a70f97c20c456a8cc271d62e9a5c621ccf6a635a1ece2d891d732a3b9
```

The conformance fixtures provide complete stage-level vectors, including tampered payload, stale
input, wrong identity, and cycle rejection cases.

## AgentEvent digest and chain

`AgentEvent.v1.event_digest` uses the same JCS and SHA-256 primitives. Create its projection by
copying the complete top-level event object and removing only the top-level `event_digest` member:

```text
event_digest = H(JCS(event_without_only_event_digest))
```

The projection retains `previous_event_digest`, identity, correlation, causation, actor, artifact
reference, stage, type, and timestamp. No nested member is removed, and there is no additional
chain-material object. A root declares `previous_event_digest: null`; every non-root stores the
exact verified `event_digest` of its predecessor.

For a requested event sequence, the verifier requires exactly one root and exact root-to-terminal
caller order. Event IDs and digests are unique; predecessor links must resolve within the supplied
set and cannot fork, cycle, or leave disconnected nodes. Every event shares one `transformation_id`
and `correlation_id`; each non-null `causation_id` names an earlier event; an `artifact_ref` carries
the event transformation; and `occurred_at` never precedes its predecessor. Any mismatch rejects
the complete event chain with no repair or reordering.

## Evidence quote digest

`EvidenceReference.v1.quote_sha256` binds the literal `exact_quote` text independently of the
enclosing artifact. It is the lowercase SHA-256 of the exact UTF-8 bytes of `exact_quote`, with no
trimming, newline conversion, Unicode normalization, or JCS string quoting. Validators also reject
a line or character range whose end precedes its start. `source_sha256` remains the digest of the
complete external source and can be verified only when that source is available.

## Security meaning

This profile proves equality to expected canonical content and binds a lineage graph. SHA-256 is not
a producer identity signature and a digest does not prove that evidence is true. A governed run must
also pin producer releases and commits, verify published provenance, protect the artifact workspace,
and preserve external authorization evidence.
