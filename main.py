from tabulate import tabulate
from utils import *
import argparse


def main():
    # Argument parsing
    parser = argparse.ArgumentParser()
    parser.add_argument("vendor", type=str, help="Vendor")
    parser.add_argument("product", type=str, help="Product")
    parser.add_argument("--min-severity", type=str, choices=["Routine", "Accelerated", "Critical"],
                        help="Show only vulnerabilities at or above this severity rating")
    args = parser.parse_args()
    vendor = args.vendor
    product = args.product
    min_severity = args.min_severity

    # Set the severity order for filtering
    severity_order = {"Routine": 1, "Accelerated": 2, "Critical": 3}

    # Fetch data
    cves = fetch_cves(vendor, product)
    kev_cves = fetch_kev_catalog()

    # Go through each vulnerability and calculate severity
    results = []
    for cve in cves:
        cve_id = cve["id"]
        cvss = cve.get("cvss")
        epss = fetch_epss(cve_id)
        in_kev = cve_id in kev_cves
        severity = calculate_severity(cvss, epss, in_kev)
        summary = cve.get("summary", "")

        if min_severity:
            if severity_order[severity] < severity_order[min_severity]:
                continue

        colored_severity = colorize_severity(severity)
        results.append([cve_id, cvss, f"{epss * 100:.1f}%", "Yes" if in_kev else "No", colored_severity, summary])

    # Display the results
    print(tabulate(results, headers=["CVE ID", "CVSS", "EPSS", "KEV", "Severity", "Summary"], tablefmt="grid"))


if __name__ == "__main__":
    main()
