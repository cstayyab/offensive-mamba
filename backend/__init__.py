from pycvesearch import CVESearch
from SystemScan import SystemScan

cve = CVESearch()
sc = SystemScan('172.28.128.3')
sc.startScan()
sc.fetchMSFE()
