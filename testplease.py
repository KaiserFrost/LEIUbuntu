import requests
from storeData import *
from managedb import databaseManager
from datetime import datetime


dbmanager = databaseManager()
rows = dbmanager.getCVEData("CVE-2012-5578")
print(rows['cveID'])
