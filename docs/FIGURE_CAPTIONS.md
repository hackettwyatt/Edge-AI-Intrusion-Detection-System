# Ready-to-use figure captions and placement

The PNGs in `screenshots/` show **exact code excerpts** from this reviewed publication copy. They are not fabricated runtime screenshots, and they are not evidence that the modified release was redeployed. Line numbers refer to the release files.

| Image | Suggested paper section | Figure caption |
| --- | --- | --- |
| `figure_01_model_training.png` | Machine learning / model development | *Figure X. HistGradientBoosting classifier configuration and model-fitting procedure in the final V4 training script.* |
| `figure_02_model_inference.png` | Distributed inference implementation | *Figure X. Numerical feature preparation, attack probability inference, and inference latency measurement on Athena.* |
| `figure_03_two_hit_policy.png` | Intrusion detection and response | *Figure X. Two-hit policy logic used to issue a temporary BLOCK decision after repeated suspicious windows.* |
| `figure_04_firewall_enforcement.png` | Automated mitigation | *Figure X. nftables command construction and Kubernetes-based firewall enforcement.* |
| `figure_05_mitigation_verification.png` | Experimental validation | *Figure X. Validation routines that inspect firewall drop counters and blocked-source membership.* |
| `figure_06_feature_extraction.png` | Feature engineering | *Figure X. Behavioral window features derived from Zeek connection records.* |

Recommended paper set: **1, 3, 4, and 5** if you only have room for four, or add **2** if you have room for five. Feature extraction is also valuable if that section needs an implementation figure.

Keep captions in your paper document rather than embedding “Figure X” inside the PNG. Cite or link the corresponding version of the repository in the code-availability subsection.
