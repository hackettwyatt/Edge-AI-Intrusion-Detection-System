# Notes on this publication snapshot

This public release was assembled from the author's final-source code review directory, updated V4 live controller and launcher, and experiment scripts/results exported from the original Zeus `ai-ids` checkout.

## Changes relative to the lab source

Changes are intentionally limited to packaging, privacy, and explicit authorization:

1. Updated Python imports from the original `simple_ids.v4` paths to the reorganized source folders in this repository.
2. Removed the original user's home-directory literals and private lab network addresses from the publication copy; introduced `AI_IDS_*` environment settings.
3. Changed the firewall enforcer to **require an explicit authorized CIDR** before any block is allowed; this fails closed when unspecified.
4. Made the infrastructure tunnel source exclusion configurable so no particular cluster address is embedded in published code.
5. Updated the launcher to invoke the packaged module layout, with the Python executable and service address supplied by configuration.
6. Added explicit opt-in requirements to the prospective holdout and 30-trial validation shell scripts, which may generate attack traffic, reset firewall state, restart services, or modify lab resources.
7. Added documentation, illustrative code figures, a minimal dependency list, and non-networking unit tests.

The feature extraction, model selection, attack classification, alert/block decision logic, and reported experiment result files were not recalculated or changed for publication.

## Material not included

- Frozen V4 `joblib` model binary and third-party/raw training datasets.
- Zeek packet captures and complete sensor logs.
- Internal-only Kubernetes configuration and private lab credentials.
- Several external helpers/resources referenced by the original evaluation harness, including `tools/sync_v4_lab_firewall.sh`.
- Original cluster installation and provisioning history (preexisting research environment).

**Reproducibility statement:** This repository makes the key source and summary evidence inspectable. Re-running every original trial would additionally require the complete authorized cluster/testbed, missing helper scripts and data, the exact model artifact, and environment-specific configuration. Tests in `tests/` are safe local logic checks; they do not reproduce live detection metrics.

## Reporting cautions

The 160-trial and 30-trial campaigns are distinct evaluations. The 197.295 ms focused defense-action measurement does not represent the 40.218 s mean traffic-to-observed-block delay. No comparative superiority over cloud deployment is established here.
