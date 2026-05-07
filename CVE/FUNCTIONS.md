# CVE Optimization & Secure Version Recommender

This tool helps you find **safe upgrade versions** for packages listed in an input json file file. It processes known vulnerabilities (CVEs), determines which versions fix them, checks for public exploits, and **validates recommendations against GitHub** to make sure you're upgrading to real, available versions.

---

## How the Process Works

The pipeline is designed in **two main steps**:

### 1. First Pass: Find Optimal Versions  
**Script:** `first_optimal_july.py`

- Reads your input file listing packages and their known CVEs.
- For each package:
  - Finds the **earliest version** that:
    - Fixes **all CVEs**, and
    - Fixes only **high and critical CVEs**.
  - Filters out:
    - Pre-release versions like alpha, beta, pre, dev
    - Malware-related CVEs (marked with MAL)
- Checks whether public **exploits exist** for each CVE.
- Validates if the recommended versions actually **exist on GitHub** — so you don't upgrade to ghost versions.
- Adds this validated recommendation to each package.

### 2. Recursive Analysis: Eliminate New CVEs  
**Script:** `recursive_july.py`

- Takes the output from the first step as input.
- For each recommended version:
  - Checks if this version has **new CVEs** that were not in the original version.
  - If so, it **recursively upgrades** to safer versions.
  - The loop continues until a version with:
    - **No new CVEs**, or
    - **No new critical/high CVEs**,  
    is found.
- GitHub validation is again used to **confirm all versions are real**.
- Ensures every final recommendation is secure and installable.

---

## What You Get in the Output

The final result is saved in an output json file, containing for each package:

- Recommended version fixing **all CVEs**
- Recommended version fixing **only high and critical CVEs**
- The version validated to exist on GitHub
- Information about **exploit presence** for each CVE (`exploit_fix`)
- Notes if a package was skipped, already safe, or excluded due to malware
- The **latest available version** for reference

---

## ▶ How to Use

1. Make sure your input file is of the format of `test.json` present in the and follows the proper structure.
2. Run the first analysis:

python first_optimal_july.py

text

3. Run recursive optimization:

python recursive_july.py

text

That's it! Your results will be in:

output_test.json

text

---

##  Highlights

- **Real versions only**: All recommendations are checked on GitHub and are guaranteed to exist.
- **Strict filtering**: Beta, pre-release, and malware-related versions or CVEs are excluded.
- **Exploit-aware**: CVEs with known public exploits are flagged for priority remediation.
- **Two outputs per package**:
  - One safe from *all* CVEs
  - One safe from *high/critical* CVEs only

---

##  Tips

- Set `GITHUB_TOKEN` as an environment variable to avoid GitHub API rate limits.
- You can inspect logs and summaries to understand decisions made for each package.
- Review the `recommendation_details` in the output if no version is suggested—it includes reasons like "already fixed" or "no safer version found".

---

Happy upgrading! 