#!/usr/bin/python
import os
import sys
from subprocess import Popen
import time
from zapv2 import ZAPv2
import urllib2
import ssl
import json
import requests
import urlparse

ZPXY = {'http':'http://localhost:8080', 'https':'http://localhost:8080'}
zproxy = None
headers = {'content-type': 'application/json', 'Authorization': 'ApiKey ubuntu:1c91563fe3c7b0d29892e80931016bf600054d4c'}

def report(progress, status):
    try:
        requests.put('http://'+sys.argv[2]+':8000/api/v1/tests/'+sys.argv[3]+'/', 
             headers=headers, verify=True, data=json.dumps({
                'percent_complete':progress,
                'status':status 
             }))
    except: pass

def quit(ret, status):
    report(100, status)
    if zproxy:
        time.sleep(3)
        zproxy.terminate()
    sys.exit(ret)

def notify(msg):
    print msg
    sys.stdout.flush()

def login_site(url):
    login_data={"newPassword":None,
                "fullApiVersion":"v310.71",
                "username":"admin",
                "password":"tintri99",
                "roles":None,
                "typeId":"com.tintri.api.rest.vcommon.dto.rbac.RestApiCredentials"}  
    requests.post('https://ttvm122.tintri.com/api/v310/flex/session/login/action=create', 
                   proxies=ZPXY,
                   data=json.dumps(login_data), 
                   verify=False, 
                   headers={'Content-type': 'application/json'})

# Test input zap-scan <URL|HOST>

# Quick test remote URL
target = sys.argv[1].strip()
if not target:
    quit(-1, 'Invalid target')

ue = urlparse.urlparse(target)
if ue.netloc:
    target = ue.netloc
target = "https://" + target

try:
    if urllib2.urlopen(urllib2.Request(target), context=ssl._create_unverified_context()) is None:
        quit(-1, 'Target unreachable')
except:
    quit(-1, 'Target unreachable')
    
work_dir = os.getcwd()

# Start ZAP proxy
notify("Starting ZAP proxy ...")

os.chdir('C:\\Program Files (x86)\\OWASP\\Zed Attack Proxy')
zproxy=Popen(['java','-jar','zap-2.6.0.jar'], stdout=open('/dev/null','w'))
for n in xrange(3):
    if zproxy.poll() is not None:
        quit(-1, 'ZAP proxy failed to start')
    time.sleep(5)

notify("ZAP proxy STARTED")
ret = 0
try:
    notify("Starting Active Scan ...")
    zap = ZAPv2(apikey='tintri99')

    zap.urlopen(target)
    time.sleep(3)
    
    scanid = zap.ascan.scan(target)
    progress = 0
    while (progress < 100):
        time.sleep(5)
        progress = int(zap.ascan.status(scanid))
        report(progress, "Scanning...") 
    
    notify("Active Scan FINISHED")
    # save JSON scan result into file
    alertsf = os.path.join(work_dir, 'alerts.json')
    with open(alertsf, 'w') as f:
        json.dump(zap.core.alerts(), f)
        f.close()
    notify("Scan result is saved to " + alertsf)
except Exception as err:
    quit(-1, str(err))

quit(0, "Finished")
