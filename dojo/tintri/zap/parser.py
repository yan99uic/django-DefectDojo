#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import json

from dojo.models import Finding

def parse_zap_result(json_output, test):
    finds = list() 
    if json_output is None:
        return finds
    try:
        with open(json_output) as jo:
            items = json.load(jo)
        for item in items:
            find = Finding(title=item['name'],
                       cwe=item['cweid'],
                       description=item['description'],
                       test=test,
                       severity=item['risk'],
                       mitigation=item['solution'],
                       references=item['reference'],
                       active=True,
                       verified=False,
                       false_p=False,
                       duplicate=False,
                       out_of_scope=False,
                       mitigated=None,
                       impact=item['confidence'],
                       numerical_severity=Finding.get_numerical_severity(item['risk']))

            find.unsaved_endpoints = []
            finds.append(find)
    except: pass
    return finds
