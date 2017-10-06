import json
import requests
import sys
import time
import uuid
import os

def do_zap_scan(boturl, target, defectdojo, tid):
    build = {"id":4,
      "jsonrpc":"2.0",
      "method":"force",
      "params":{"builderid":"2",
                "null":"",
                "branch":"",
                "project":"",
                "repository":"",
                "revision":"",
                "target":target,
                "defectdojo":defectdojo,
                "report_tid":str(tid)}}
    # request for buildbot build
    done = False
    try:
        response = requests.post(boturl + '/api/v2/forceschedulers/forceScan',
           data=json.dumps(build), 
           headers={'Content-type': 'application/json'})
        bid = str(response.json()['result'][0])
    
        # wait for a few to catch quick errors
        for n in xrange(3):
            resp = requests.get(boturl + '/api/v2/builds/' + bid + '/steps').json()
            steps = resp['steps']
            if steps:
                for s in steps:
                    if not s['complete']:
                        break
                    if not 0 == s['results']:
                        ret = s['state_string'] 
                        done = True
                        break
                if done:
                    break
            time.sleep(5)
        if not done:
            ret = "Bot job scheduled"
    except Exception as err:
        done = True
        ret = str(err)
        if len(ret) > 70:
            ret = ret[:70] + '..' 
    return ret, done
