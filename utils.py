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
    return data


def fetch_kev_catalog():
    """
    Fetch Known Exploited Vulnerabilities (KEV) catalog from CISA.
    :return: the kev catalog cveIDs only
    """
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    resp = requests.get(url)
    resp.raise_for_status()
    data = resp.json()
    return data


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
    return data


if __name__ == "__main__":
    result = fetch_cves("Microsoft", "windows_10")
    # result = fetch_epss("CVE-2022-48503")
    # result = fetch_kev_catalog()
    print(result)

