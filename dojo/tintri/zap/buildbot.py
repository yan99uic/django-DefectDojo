import json
import requests
import sys
import time
import uuid
import os

def do_zap_scan(boturl, sites):
    rptf = os.path.join("/tmp", str(uuid.uuid1()) + ".json")
    build = {"id":4,
      "jsonrpc":"2.0",
      "method":"force",
      "params":{"builderid":"2",
                "null":"",
                "branch":"",
                "project":"",
                "repository":"",
                "revision":"",
                "instance_urls":sites,
                "report_file":rptf}}
    # request for buildbot build
    try:
        response = requests.post(boturl + '/api/v2/forceschedulers/forceScan',
           data=json.dumps(build), 
           headers={'Content-type': 'application/json'})
        bid = str(response.json()['result'][0])
    
        # wait for build to finish
        ret = True
        while True:
            resp = requests.get(boturl + '/api/v2/builds/' + bid + '/steps').json()
            done = True
            steps = resp['steps']
            if steps:
                for s in steps:
                    if not s['complete']:
                        done = False
                        break
                    if not 0 == s['results']:
                        ret = False 
                        break
                if done:
                    break
            time.sleep(5)
        # return report file if scan finished successfully
        return rptf if ret else None
    except Exception as err:
        print err
        return None






