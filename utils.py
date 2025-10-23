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
        cvss = 0.0
        metrics = cna.get("metrics", [])
        if metrics:
            for metric in metrics:
                cvss_data = metric.get("cvssV3_1", metric.get("cvssV3_0", {}))
                if cvss_data:
                    cvss = float(cvss_data.get("baseScore", 0))
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


if __name__ == "__main__":
    result = fetch_cves("Microsoft", "windows_10")
    # result = fetch_epss("CVE-2022-48503")
    # result = fetch_kev_catalog()
    print(result)

