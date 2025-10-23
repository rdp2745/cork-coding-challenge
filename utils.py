import requests


def fetch_cves(vendor: str, product: str):
    """
    Fetch CVEs for a given vendor and product from cve.circl.lu API.
    :param vendor: Vendor name
    :param product: Product name
    :return: Full CVE data from the API
    """
    url = f"https://cve.circl.lu/api/search/{vendor}/{product}"
    resp = requests.get(url)
    resp.raise_for_status()
    data = resp.json()

    cve_list = []
    nvd_entries = data.get("results", {}).get("nvd", [])

    for entry in nvd_entries:
        # Get the cve_id
        cve_id = entry[0].upper()

        # Enter the cna container
        cna = entry[1].get("containers", {}).get("cna", {})

        # Get the title and date
        title = cna.get("title", "No title available")
        date = cna.get("datePublic", "Unknown date")

        # Get the cvss and summary
        cvss = None
        metrics = cna.get("metrics", [])
        if metrics:
            for metric in metrics:
                cvss_data = metric.get("cvssV3_1", metric.get("cvssV3_0", {}))
                if cvss_data and "baseScore" in cvss_data:
                    try:
                        cvss = float(cvss_data["baseScore"])
                    except (TypeError, ValueError):
                        cvss = None
                    break
        # Create the dict entry
        cve_list.append({
            "id": cve_id,
            "cvss": cvss,
            "summary": title,
            "published": date
        })

    # Sort by publish date descending
    cve_list.sort(key=lambda x: x.get("published", ""), reverse=True)

    # Return the 10 most recent CVEs
    return cve_list[:10]


def fetch_kev_catalog():
    """
    Fetch Known Exploited Vulnerabilities (KEV) catalog from CISA.
    :return: the kev catalog cveIDs only
    """
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    resp = requests.get(url)
    resp.raise_for_status()
    data = resp.json()
    # Only return the cveIDs
    kev_cves = {item["cveID"] for item in data.get("vulnerabilities", [])}
    return kev_cves


def fetch_epss(cve_id: str):
    """
    Fetch EPSS score for a given CVE ID.
    :param cve_id: CVE identifier
    :return: epss score as float
    """
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    resp = requests.get(url)
    resp.raise_for_status()
    data = resp.json()
    # Only return the epss score
    score = data.get("data", [{}])[0].get("epss", 0)
    return float(score) if score else 0


def calculate_severity(cvss: float, epss: float, in_kev: bool) -> str:
    if cvss is None:
        if epss >= 0.75:
            return "Critical"
        elif epss >= 0.4:
            return "Accelerated"
        else:
            return "Routine"

    if in_kev and (cvss >= 8 and epss >= 0.6):
        return "Critical"
    elif in_kev and (cvss >= 7 or epss >= 0.5):
        return "Accelerated"
    else:
        return "Routine"


def analyze_vendors(vendor_product_pairs):
    """Run multiple vendors/products and average severity categories."""
    kev_set = fetch_kev_catalog()
    summary = []
    i = 0

    # Go through multiple vendors/products and total the category count of the severity function
    for vendor, product in vendor_product_pairs:
        i += 1
        print(f"\nTesting {i}: {vendor} {product} ...")
        cves = fetch_cves(vendor, product)

        counts = {"Critical": 0, "Accelerated": 0, "Routine": 0}
        total = 0

        for cve in cves:
            epss = fetch_epss(cve["id"])
            in_kev = cve["id"] in kev_set
            severity = calculate_severity(cve["cvss"], epss, in_kev)
            counts[severity] += 1
            total += 1

        if total > 0:
            summary.append({
                "vendor": vendor,
                "product": product,
                "Critical": counts["Critical"],
                "Accelerated": counts["Accelerated"],
                "Routine": counts["Routine"],
                "Total": total
            })

    # Compute averages
    avg = {"Critical": 0, "Accelerated": 0, "Routine": 0}
    if summary:
        for s in summary:
            for key in avg:
                avg[key] += s[key] / len(summary)

    total_avg = avg["Critical"] + avg["Accelerated"] + avg["Routine"]
    for key, val in avg.items():
        pct = (val / total_avg) * 100 if total_avg > 0 else 0
        print(f"{key}: {val:.2f} ({pct:.1f}%)")

    return summary, avg


if __name__ == "__main__":
    # result = fetch_cves("Microsoft", "windows_10")
    # result = fetch_epss("CVE-2022-48503")
    # result = fetch_kev_catalog()
    vendors_to_test = [
        ("microsoft", "windows_10"),
        ("adobe", "acrobat_reader"),
        ("apple", "ios"),
        ("google", "chrome"),
        ("apache", "http_server"),
        ("redhat", "enterprise_linux"),
        ("cisco", "ios_xe"),
        ("fortinet", "fortios"),
        ("canonical", "ubuntu_linux")
    ]
    analyze_vendors(vendors_to_test)

