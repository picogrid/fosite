# Picogrid Fosite maintenance

This fork adopts the Go JOSE v4 migration from
[Ory Fosite PR 892](https://github.com/ory/fosite/pull/892).
Picogrid maintains this dependency until a compatible upstream release provides
the migration. Original authorship, license and notices remain in effect.

## Source provenance

- Upstream repository: https://github.com/ory/fosite
- Upstream base: `a5f0b09bf31c17297b25637bb3fec2ff7a55b159`
- Reviewed PR head: `45f474113e7b581862202d327964242b9b52dd1e`
- Maintenance branch: `emil/jose-v4`
- Initial fork release: `v0.49.1-picogrid.1`.
- Picogrid changes: independent legacy-token regression test, patched dependency
  minimums aligned with the consuming application, and CI that tests this
  checkout with normal and race suites on Go 1.26.10.
- Go JOSE dependency: official `github.com/go-jose/go-jose/v4 v4.1.6`.
- Minimum Go toolchain: 1.26.10. This exceeds the PR's 1.24 minimum because the
  patched dependency versions require the newer toolchain.

The module path remains `github.com/ory/fosite`, preserving upstream package
imports. Consumers select the fork using a Go module replacement pinned to a
Picogrid tag or immutable commit. Replacements must be configured in each main
module; dependencies' replacements are not inherited. Local filesystem
replacements are for development only and must not appear in release manifests.

```go
replace github.com/ory/fosite => github.com/picogrid/fosite v0.49.1-picogrid.1
```

## Validation

The exact reviewed PR head passed the complete normal and race suites locally.
Both suites passed again with the additional Picogrid regression test. That
test validates a token produced by Go JOSE v3.0.5, verifies preserved claims and
tamper rejection, and independently verifies newly signed tokens using Go's
standard library. Consumer OAuth flow tests must also pass before adoption.
The fork's patched dependency set also passes a fresh CycloneDX schema check
and vulnerability scan with no high/critical findings under Trivy-selected or
embedded vendor ratings. These are source-inventory results, not a claim about
every downstream deployment.

```sh
go mod verify
go test -count=1 ./...
go test -race -count=1 ./...
```

Go JOSE v4 JWT parsing accepts compact JWT serialization. Consumers that relied
on JSON JWS serialization must evaluate that compatibility change explicitly.
Valid RSA JWKs are subject to the upstream library's size limits, including its
default 4096-bit modulus bound. Do not weaken algorithm or key validation to
restore unsafe inputs.

The upstream Hydra conformity workflow is not sufficient evidence for this
fork's consumer compatibility: it checks out a separate application. The normal
and race workflow above tests the actual Fosite checkout. This fork does not
claim independent OIDC certification.

## Releases and maintenance

Use a Picogrid-specific version, such as `v0.49.1-picogrid.1`, and record its
exact commit. Do not move published tags. Carry the base commit, PR head, fork
commit, module checksum and patch provenance into consumer SBOM evidence.
CycloneDX pedigree should identify the upstream ancestor; a new package URL
alone is not proof that upstream vulnerabilities are fixed.

Review upstream Fosite and Go JOSE advisories for every release, including
advisories that scanners do not match to the fork's package URL. Refresh the
consumer dependency inventory and run regression tests after each update.
Picogrid owns release and patch maintenance until the fork is retired.
