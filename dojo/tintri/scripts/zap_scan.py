#!/usr/bin/python
import os
import sys
from subprocess import Popen
import time
from zapv2 import ZAPv2
import urllib2
import ssl
import json

def fail(err):
    print err
    sys.exit(-1)

def notify(msg):
    print msg
    sys.stdout.flush()

# Test input zap-scan <URL>
if len(sys.argv) < 2:
    fail('Usage: zap-scan URLs')

# Quick test remote URL
targets = []
for u in sys.argv[1].split(','):
    url = u.strip() 
    if not url.startswith('http'):
        url = "https://" + url
    try:
        if urllib2.urlopen(urllib2.Request(url), context=ssl._create_unverified_context()) is not None:
            targets.append(url)
    except:
        print 'instance URL not available: ', url

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
