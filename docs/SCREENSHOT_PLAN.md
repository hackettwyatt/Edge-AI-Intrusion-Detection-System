# Code figures for the master's research paper

Capture **four or five focused figures**, each showing a readable function or short code block from the **publication copy** of the project. Prefer a screenshot that demonstrates a design decision, not an entire screen of dense code.

| Priority | Source | Capture | Proposed caption |
| --- | --- | --- | --- |
| 1 | `defense/defense_policy.py` | The condition requiring two qualifying classifications within the policy time window | *Figure X. Implementation of the two-hit alert-to-block response policy.* |
| 2 | `live_ids/v4_metrics_server.py` | The `/predict` endpoint or model loading and probability generation | *Figure X. V4 model inference service used to classify source-based network traffic windows.* |
| 3 | `defense/firewall_enforcer.py` | The function that applies a temporary nftables block | *Figure X. Automated firewall enforcement implementation for a detected source.* |
| 4 | `supporting/features.py` or `model_pipeline/build_local_windows.py` | Source-based traffic features and 10-second window construction | *Figure X. Construction of behavioral features from network connection records.* |
| 5 (optional) | `evaluation/run_defense_validation_30.sh` or `evaluation/repeated_trial_runner.py` | The experiment control or independent mitigation verification logic | *Figure X. Controlled attack and mitigation validation procedure.* |

## Capture guidelines

1. Open the file in VS Code using the **separate publication copy**.
2. Show the function name plus approximately 12–30 meaningful lines; avoid tiny text.
3. Turn on line numbers, choose a high-contrast theme, and use readable zoom.
4. Remove or mask private addresses, credentials, personal paths, and identifying terminal content **before** capturing.
5. Use Windows Snipping Tool (`Win` + `Shift` + `S`) or your preferred screenshot utility.
6. Save images as descriptive PNGs, for example `figure_two_hit_policy.png`.
7. Place the figure near the relevant explanation in the paper and refer to it explicitly in the text.
8. After publishing, consider linking the exact GitHub file or commit permalink in the figure caption or code-availability note.

The screenshots are supporting evidence; code listings and a reproducible GitHub release are more useful than screenshots alone. Use a figure of the actual experimental results separately from the code screenshots where appropriate.
