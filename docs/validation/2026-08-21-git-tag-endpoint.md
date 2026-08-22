# Annotated Git tag-object endpoint validation — 2026-08-21

Status: **typed read-only transport and mock contract passed; live nested-tag
shape and collector integration remain pending**

> **Follow-up, 2026-08-22:** collector integration and the controlled live
> annotated-tag-to-commit path now pass. The collector preserves the recorded
> tag object separately from its peeled commit; see the
> [controlled-lab qualification](2026-08-22-controlled-lab-qualification.md).
> The status above is retained as this dated transport milestone. Live nested
> tag-to-tag and SHA-256 repository shapes remain outside the qualified matrix.

This bounded change adds the read-only transport prerequisite for preserving
and later peeling an annotated reusable-workflow tag object. It does not modify
the live collector, classify an existing reusable-workflow SHA as a tag or
commit, perform a GitHub write, or make a live GitHub request.

## Primary source

The official [Git database tag endpoint](https://docs.github.com/en/rest/git/tags?apiVersion=2026-03-10#get-a-tag),
retrieved 2026-08-21, documents:

- `GET /repos/{owner}/{repo}/git/tags/{tag_sha}`;
- GitHub API version `2026-03-10` and the standard GitHub JSON media type;
- repository **Contents: read** for fine-grained PATs and GitHub Apps, with
  unauthenticated access for public resources;
- `200`, `404`, and `409` responses;
- the annotated tag object's own `sha`, `tag`, and `node_id`; and
- a target `object` with distinct `type` and `sha` fields.

GitHub explicitly describes this API family as operating on annotated tag
objects, not lightweight tags. Its current create-tag documentation enumerates
`commit`, `tree`, and `blob` target types. Git itself permits a tag object to
target another tag object, so the typed client accepts `tag` as a defensive
target kind and tests it. That nested response shape must be confirmed in the
controlled GitHub lab before the collector depends on it.

## Implemented transport contract

`Client.GetGitTag` accepts only an owner, repository, and a complete typed
`GitObjectID`. Before any request it requires:

- algorithm exactly `sha1` or `sha256`;
- respectively 40 or 64 characters;
- lowercase hexadecimal; and
- no ref, branch, tag name, URL, or untyped abbreviated SHA.

The only compiled route is the read-only C2a route. There is no exported generic
URL/request method. The normalized result intentionally omits API URLs and keeps:

```text
GitTagObject.TagObjectID
GitTagObject.TagName
GitTagObject.NodeID
GitTagObject.Target.Kind
GitTagObject.Target.ObjectID
```

The response is rejected as malformed unless the returned tag-object ID is
complete, typed with the requested repository algorithm, and exactly equals the
requested tag-object ID. The target kind must be one of `commit`, `tag`, `tree`,
or `blob`, and its ID must independently be complete lowercase hexadecimal for
the same algorithm. Neither ID overwrites the other.

Every HTTP attempt retains the existing sanitized `ResponseMeta`: `GET`, route
template rather than raw URL, bounded request parameters, status/request ID,
selected API/media versions, complete-body length and SHA-256, timing, rate
headers, and normalized error class. No authorization header, token, response
URL, target URL, or raw body enters the typed result or diagnostic.

## Mock coverage

Deterministic `httptest` coverage includes:

- SHA-1 annotated tag object targeting a distinct commit;
- SHA-256 annotated tag object targeting another distinct tag object;
- exact method/path/header and normalized-response metadata;
- strict rejection of missing/unsupported algorithms, short IDs, uppercase
  IDs, and nonhexadecimal IDs before a request;
- malformed JSON, absent fields, mismatched returned tag ID, unsupported target
  type, short target ID, and uppercase target ID;
- sanitized `404` with response provenance retained; and
- a pre-cancelled context causing no request while preserving
  `context.Canceled` as the typed error cause.

## Proposed later peel algorithm

The transport deliberately performs one hop only. Later collector integration
should use this bounded derivation:

1. Preserve the original GitHub-recorded reusable-workflow object ID exactly as
   its own fact before probing. Obtain the repository hash algorithm
   independently; never guess from a prefix or assume SHA-1.
2. Use a maximum of **eight tag-object hops**. Maintain a `seen` set keyed by
   `(algorithm, full object ID)`, initialized with the first probed object. Cache
   one-hop C2a results by repository identity plus that key.
3. On each successful C2a response, persist the tag object, typed target, full
   response metadata/evidence ID, and an explicit tag-points-to derivation. Do
   not rename the tag object as a commit or overwrite the original run metadata.
4. If the target kind is `commit`, return that separate target ID as the peeled
   workflow-definition candidate with the complete tag chain supporting it.
5. If the target kind is `tag`, reject a self-edge or any target already in
   `seen`; otherwise add it and fetch the next hop. A ninth hop stops with a
   parser/derivation-limit evidence gap, retaining all eight observations.
6. If the target kind is `tree` or `blob`, stop as an unsupported workflow
   target. Preserve the typed edge and report a reconstruction gap; never pass
   that object to historical workflow-content retrieval as a commit.
7. On `403`, `404`, `409`, cancellation, size/media failure, malformed response,
   or rate exhaustion, stop and retain the normalized error and collected
   prefix. In particular, **C2a `404` is not proof that the current object is a
   commit**.
8. For an initially recorded SHA that produces C2a `404`, require a separate
   positive typed-commit observation (a future narrow Git-commit endpoint or
   another source whose semantics explicitly establish commit type) before
   labeling it a commit. Until then, keep its type unknown even if existing
   historical-content APIs happen to accept it.

The depth of eight is a defensive implementation bound, not a GitHub semantic
limit. Cycle, depth, unsupported-type, and unavailable-evidence outcomes must be
visible coverage gaps rather than silent fallback.

## Remaining validation

- Create harmless controlled tag-object chains and confirm GitHub.com's actual
  `tag -> tag` response type, SHA-256 repository behavior when available, and
  permission/error responses.
- Add the narrow positive commit-object lookup needed to distinguish an initial
  commit from a missing tag object without inferring from `404`.
- Integrate one-hop observations and peel derivations into the archive/evidence
  schema before changing reusable-workflow content identity.
- Ensure replays preserve the original object and can re-derive a peeled commit
  when later tag observations or parser versions become available.
