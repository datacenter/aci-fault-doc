#!/usr/bin/env python

import argparse
import requests
from bs4 import BeautifulSoup, Tag, NavigableString
import re
import json
import getpass

def getApicFaults(session, apicUrl=None, name='admin', pwd=None):
    ''' retrieves all faultInst from APIC and returns data as dictionary '''
    if apicUrl is None or name is None or pwd is None:
        raise Exception("Incomplete APIC login info")
    # login to apic
    loginUrl = "/api/aaaLogin.json"
    login_data = {"aaaUser":{"attributes":{"name":name, "pwd":pwd}}}
    response = session.post(apicUrl + loginUrl, data=json.dumps(login_data), verify=False).json()['imdata'][0]
    if 'error' in response:
        raise Exception(response['error']['attributes']['text'])
    # query apic for all faultInst MOs
    faultQuery = '/api/class/faultInst.json'
    response = session.get(apicUrl + faultQuery).json()['imdata']
    if len(response) > 0 and 'error' in response[0]:
        raise Exception(response['error']['attributes']['text'])
    return response

def getFaultDocumentation(session, apicUrl, faults):
    ''' retrieves fault documentation from APIC using requests sessions '''
    docUrl = '/doc/html/'
    faultUrl = 'FaultMessages.html'
    faultsHtml = BeautifulSoup(session.get(apicUrl + docUrl + faultUrl, verify=False).content)
    last_fault_code = None
    for fault_row in filter(lambda x: x.name == 'tr', faultsHtml.table.tbody.children):
        columns = filter(lambda x: x.name == 'td', fault_row.contents)
        if len(columns) > 0:
            if columns[0].string == 'Fault Code':
                last_fault_code = columns[-1].string.encode('ascii',errors='ignore')
            if columns[0].string == 'Fault Name':
                if last_fault_code in faults:
                    faults[last_fault_code]['documentation']['url'] = columns[-1].find('a')['href']
    
    tags_to_skip = ['a', 'br', 'p', 'tr', 'td', 'b', 'ol', 'li']
    for code in faults:
        if 'url' in faults[code]['documentation']:
            faultHtml = BeautifulSoup(session.get(apicUrl + docUrl + faults[code]['documentation']['url'], verify=False).text).body
            for tag in faultHtml.find_all('b'):
                if isinstance(tag.next_sibling, basestring) and tag.next_sibling.startswith(':'):
                    faults[code]['documentation'][tag.string] = []
            last_match = ''
            for tag in faultHtml.descendants:
                if tag.name == 'b' and tag.string in faults[code]['documentation']:
                    last_match = tag.string
                elif last_match != '':
                    strings = []
                    if isinstance(tag, NavigableString) and tag != last_match:
                        strings = re.sub('^:[ ]+', '', tag.encode('ascii',errors='ignore')).split('\n')
                    elif isinstance(tag, Tag) and tag.string is not None and tag.name not in tags_to_skip:
                        strings = tag.string.split('\n')
                    elif isinstance(tag, Tag) and (tag.name == 'br' or tag.name == 'li'):
                        strings = ['\n']
                    strings = [x.strip(' :') for x in strings if x.strip(' :') != '']
                    for x in strings:
                        faults[code]['documentation'][last_match].append(x)
    return faults

def printFaultSummary(faults):
    print "FAULT SUMMARY (grouped / sorted by # of occurrences)"
    print "+" * 80
    print
    for k, v in sorted(faults.iteritems(), key=lambda (k,v): (v['occurrences'],k), reverse=True):
        log = "FAULT: " + k
        if 'url' in v['documentation']:
            log += ", NAME: " + ' '.join(v['documentation']['Fault Name']).rstrip('\n').replace('\n', '\n      ')
        print log + ", occurred: " + str(v['occurrences'])
    print
    print "+" * 80
    print

def printFaultDocumentation(faults, documentation=False):
    print "FAULT DOCUMENTATION (grouped / sorted by # of occurrences)"
    print "+" * 80
    print
    for k, v in sorted(faults.iteritems(), key=lambda (k,v): (v['occurrences'],k), reverse=True):
        print "FAULT: %s - %d occurrences" % (k, v['occurrences'])
        if documentation:
            if 'url' in v['documentation']:
                for key in ['Fault Name', 'Message', 'Severity', 'Type', 'Cause', 'Explanation', 'Recommended Action']:
                    if len(v['documentation'][key]) > 0:
                        value = ' '.join(v['documentation'][key]).rstrip('\n').replace('\n', '\n      ')
                        print "    %s: %s" % (key, value)
            else:
                print "    DOCUMENTATION NOT AVAILABLE"
        print
        print "    Instances (first 10):"
        for instance in sorted(v['instances'])[:10]:
            print "        %s %s" % (instance['severity'], instance['dn'])
            if instance['descr'] != "":
                print "            %s" % instance['descr']
        print
        print "-" * 80
        print
    print "+" * 80

def main(apicUrl=None, name=None, pwd=None, documentation=False, apic_faults=None):
    faults = {}
    session = requests.Session()
    if apic_faults is None:
        apic_faults = getApicFaults(session, apicUrl, name, pwd)
    for x in apic_faults:
        code = x['faultInst']['attributes']['code']
        if code not in faults:
            faults[code] = {'occurrences':0, 'instances':[], 'documentation':{}}
        faults[code]['occurrences'] += 1
        faults[code]['instances'].append(x['faultInst']['attributes'])
    if documentation == True:
        getFaultDocumentation(session, apicUrl, faults)
    printFaultSummary(faults)
    printFaultDocumentation(faults, documentation)

if __name__ == '__main__':
    parent_parser = argparse.ArgumentParser(description='APIC Fault summary')
    parent_parser.add_argument('apicUrl', help='APIC URL (http or https should be included)', type=str)
    parent_parser.add_argument('--username', type=str, help='username', default="admin")
    parent_parser.add_argument('--pwd', type=str, help='password', default=None)
    parent_parser.add_argument('--json', type=str, help='load faults from json file (expects full json response by APIC)')
    args = parent_parser.parse_args()
    if re.match('http', args.apicUrl) is None:
        args.apicUrl = 'https://' + args.apicUrl
    if args.pwd is None:
        args.pwd = getpass.getpass()
    apic_faults = None
    if args.json is not None:
        with open(args.json) as fp:
            apic_faults = json.load(fp)['imdata']
    main(apicUrl=args.apicUrl, name=args.username, pwd=args.pwd, documentation=True, apic_faults=apic_faults)
