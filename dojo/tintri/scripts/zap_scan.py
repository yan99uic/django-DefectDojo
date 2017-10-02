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

def fail(err):
    print err
    sys.exit(-1)

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
if len(sys.argv) < 2:
    fail('Usage: zap-scan URLs/hosts')

# Quick test remote URL
targets = []
for t in sys.argv[1].split(','):
    th = u.strip()
    if not th:
        continue
    ue = urlparse.urlparse(th)
    if ue.netloc:
        th = ue.netloc
    try:
        if urllib2.urlopen(urllib2.Request('https://'+th), context=ssl._create_unverified_context()) is not None:
            targets.append(th)
    except:
        print 'instance not available: ', t

if not targets:
    fail('none of the target is accessible')

work_dir = os.getcwd()

# Start ZAP proxy
notify("Starting ZAP proxy ...")

os.chdir('C:\\Program Files (x86)\\OWASP\\Zed Attack Proxy')
zproxy=Popen(['java','-jar','zap-2.6.0.jar'], stdout=open('/dev/null','w'))
for n in xrange(3):
    if zproxy.poll() is not None:
        print "ZAP Proxy failed to start"
        sys.exit(-1)
    time.sleep(5)
notify("ZAP proxy STARTED")
ret = 0
try:
    notify("Starting Active Scan ...")
    zap = ZAPv2(apikey='tintri99')
    for target in targets:
        zap.urlopen(target)
        time.sleep(3)
        scanid = zap.ascan.scan(target)
        while (int(zap.ascan.status(scanid)) < 100):
            time.sleep(5)
    
    notify("Active Scan FINISHED")
    # save JSON scan result into file
    alertsf = os.path.join(work_dir, 'alerts.json')
    with open(alertsf, 'w') as f:
        json.dump(zap.core.alerts(), f)
        f.close()
    notify("Scan result is saved to " + alertsf)
except Exception as err:
    print err
    ret = -1

time.sleep(3)
zproxy.terminate()
sys.exit(ret)
