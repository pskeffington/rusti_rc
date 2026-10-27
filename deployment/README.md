# Offline package metadata scaffold

The [candidate JSON Schema](release-manifest.schema.json) is a *data-shape proposal only*. No production rusti_rc release payload, signer, hardware-protected trust-root verifier, installer or updater exists yet. The [G2g-A laboratory verifier](../docs/deployment/G2G_SIGNED_BUNDLE_LAB.md) checks synthetic signed manifests and payloads but cannot install or approve a release.

## Required verification order

1. Do not trust **any** field inside a candidate manifest until a previously provisioned, approved trust root verifies its detached signature **over the exact raw manifest bytes**.
2. Validate the signed payload against the strict versioned schema; unknown fields must fail unless explicitly migrated. JSON Schema validity alone is neither authenticity nor proof of correct version sequencing.
3. Enforce `security_floor_epoch <= release_epoch` and a separately protected local security floor. Check expiry and trustworthy time before treating an offline update as fresh. A signature does **not** make a revoked/vulnerable old release safe.
4. Check exact machine architecture, OS kernel/ABI and CPU requirements, including glibc/musl and C crypto dependencies. An architecture string by itself does not establish executable compatibility.
5. Validate every archive path: normalize once, reject absolute paths, `..`, path separators incompatible with the host, symlinks/hardlinks/alternate streams, device files, duplicate names and extraction outside a staging directory. Never trust a JSON path without file-system checks.
6. Verify digest/size for each file, reject additional undeclared executable files, and stage under a nonprivileged installation directory.
7. Preserve state outside the binary slot, use atomic activation and record a local signed release receipt. Do not write credential material to bundle metadata.
8. Only then permit an explicit operator-controlled launch, with networking still disabled until separate authorization.

The schema does not implement the secure-update protections of [TUF](https://theupdateframework.io/docs/security/). It is intended to support later design and review, not to replace TUF roles, key rotation or signed timestamp/snapshot/target metadata.

See [offline redeployment runbook](../docs/deployment/OFFLINE_REDEPLOYMENT_RUNBOOK.md) and [release checklist](../docs/security/RELEASE_CHECKLIST.md) before implementing this interface.
