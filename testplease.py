import requests
from storeData import *
from datetime import datetime
'''cpematch = "https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString="
cpe = "cpe:2.3:a:python:keyring:*:*:*:*:*:*:*:*"
getcpe = requests.get(cpematch +cpe)
if getcpe.ok:
    data = getcpe.json()
    StoreCVE(data,cpe)'''

print("2020-07-17" - datetime.today().strftime('%Y-%m-%d'))