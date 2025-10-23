# CVE Analysis Tool

This project provides a Python-based tool for analyzing Common Vulnerabilities and Exposures (CVEs) for specific vendors and products. It fetches CVE data, calculates severity levels, and displays the results in a tabular format.

## Features

- Fetch CVE data from the `cve.circl.lu` API.
- Retrieve Known Exploited Vulnerabilities (KEV) catalog from CISA.
- Fetch Exploit Prediction Scoring System (EPSS) scores from the FIRST API.
- Calculate severity levels based on CVSS, EPSS, and KEV inclusion.
- Display results in a colorized table with filtering options.
- Analyze multiple vendors and products to compute average severity statistics.

## Logic for Severity Rating calculation
My thought process for calculating the severity rating was to have thresholds that determine the category of severity. 
Initially, I created a basic if else structure that checks for KEV inclusion first, then EPSS score, and finally CVSS score to assign a severity rating.
However, this led to almost every vulnerability being rated as "Critical" due to the KEV inclusion.
So, I then created a simple analytics function that runs through multiple vendor/product combinations, assigns a severity rating
and then calculates the average severity rating and the percentage of total vulnerabilities in each category. 
Based on this, I wanted to then adjust the thresholds such that the critical is around 20%, accelerated around 30%, and routine around 50%.
I thought this would make sense since critical vulnerabilities should be less frequent than routine ones.
However, I then realized that some cvss scores were not present in the data, so I added an initial calculation with just the KEV inclusion and epss score 
if the CVSS score was not present in the data. 
The final thresholds were:
- If no CVSS score:
  - Critical: KEV included and EPSS >= 0.75
  - Accelerate: KEV included and EPSS >= 0.4
  - Routine: All others
- If CVSS score present:
  - Critical: KEV included and (CVSS >= 8 or EPSS >= 0.6)
  - Accelerate: KEV included and (CVSS >= 7 or EPSS >= 0.5)
  - Routine: All others

## Requirements

- Python 3.7+
- Dependencies:
  - `requests`
  - `tabulate`
  - `argparse`

Install the required dependencies using:

```bash
pip install -r requirements.txt
```

## Usage
Run the script with the desired vendors and products:

```bash
python main.py Vendor Product--min-severity SeverityLevel
```
Example:
```bash
python main.py Microsoft windows_10 --min-severity Accelerate
```

