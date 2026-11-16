# Publishing this IDS research snapshot on GitHub

## Before publishing

1. Extract the release archive into a **new folder** on your PC or Zeus; do **not** extract it over the working `/home/zues/ai-ids` installation.
2. Open [`README.md`](../README.md), [`.env.example`](../.env.example), and [`PUBLICATION_NOTES.md`](PUBLICATION_NOTES.md).
3. Check that no sensitive values, personal files, or dataset/PCAP files were added while extracting.
4. Decide whether to add a software license (such as MIT or Apache-2.0). Public visibility alone does **not** grant unrestricted reuse rights.
5. Use an empty repository on GitHub (create it **without** adding a second README or `.gitignore`).

## Push the clean snapshot

From a terminal **inside the extracted release folder**, run:

```bash
git init
git branch -M main
git add -A
git status --short
git diff --cached --check
git commit -m "Publish IDS master's research source and evaluation summaries"
git remote add origin https://github.com/YOUR_USERNAME/Edge-AI-Intrusion-Detection-System.git
git push -u origin main
```

Replace `YOUR_USERNAME` with your own GitHub username. Configure Git author details or follow the account sign-in prompt if prompted. **Review `git status --short` before committing:** only the documented files, tests, figures, and aggregate results should be staged.

If the repository already exists and contains commits, stop and check its contents before setting a remote or pushing; do not force-push over existing work.

## Link it from the paper

Once the files are visible on GitHub:

1. Create a tagged release (for example `v1.0-defense`) representing the code submitted with the paper.
2. Put the stable release URL in your manuscript's *Source Code Availability* subsection.
3. For a code screenshot, link to the exact file at that release tag (or a commit permalink) in the caption/appendix.
4. Cite the software using the citation format required by your university. The included `CITATION.cff` provides repository metadata.

Suggested text:

> The source code for the AI-assisted intrusion detection and automated response pipeline, including model-training, live inference, defense policy, firewall enforcement, and evaluation scripts, is available at [GitHub release URL]. Aggregate results from the 160-trial broad evaluation and 30-trial focused validation are included. The repository documents a controlled research prototype and requires additional cluster-specific resources for full experimental replication.

Do not describe the existing Raspberry Pi Kubernetes cluster itself as software created by the researcher.
