#!/usr/bin/python
# by Konrads Smelkovs <konrads.smelkovs@kpmg.co.uk>
# Shouts to Sash :)
# Licence - CC-BY, else do whatever you want with this

import urllib2
import json
import time
import sys
import argparse
import ssl
import os

try:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
except AttributeErorr, e:
    print "You should have python version 2.7.9 or later"
    print str(e)
    sys.exit(-1)

SLEEP = 2
CHOICES = "csv nessus html".split(" ")
DEF_URL = "https://localhost:8834"
parser = argparse.ArgumentParser(description='Download Nesuss results in bulk')
parser.add_argument('--sleep', type=int, default=SLEEP,
                    help='poll/sleep timeout')
parser.add_argument('--url', '-u', type=str, required=True,
                    default=DEF_URL,
                    help="url to nessus instance, default {}".format(DEF_URL))
parser.add_argument('-l', '--login', type=str, required=True,
                    help='Nessus login')
parser.add_argument('-p', '--password', type=str, required=True,
                    help='Nessus password')
parser.add_argument('-f', '--format', type=str, required=True,
                    default="csv", choices=CHOICES,
                    help='Format of nesuss output, defaults to csv')
parser.add_argument('--debug', type=bool, default=False,
                    help='Enable debugging output')
parser.add_argument('-o', '--output', type=str,
                    help='Output directory')
parser.add_argument('-f', '--folder' metavar='FOLDER', type=str, nargs=1,
                    help='Folder from which to download  (My Scans = Folder No. 2', 
                        required=True)
args = parser.parse_args()

if args.output:
    OUTPUDIR = args.output
else:
    OUTPUDIR = os.getcwd()

if args.sleep:
    SLEEP = args.sleep


data = json.dumps({'username': args.login, 'password': args.password})
request = urllib2.Request(args.url + "/session", data, {'Content-Type': 'application/json; charset=UTF-8',
                                                        })
# opener.open(request,context=ctx)
f = urllib2.urlopen(request, context=ctx)
token = json.loads(f.read())['token']
if args.debug:
    print "[D] Logged on, token is %s" % token


request = urllib2.Request(args.url + "/folders",
                          headers={'X-Cookie': 'token=' + str(token)})
f = urllib2.urlopen(request, context=ctx)
folders = json.loads(f.read())
# print folders
# print args.scanfolder[0]
folderid = filter(lambda y: y['name'] == args.scanfolder[
                  0], folders['folders'])[0]['id']


scans_by_folder = urllib2.Request(
    args.url + "/scans?folder_id=%i" % folderid, headers={'X-Cookie': 'token=' + str(token)})
f = urllib2.urlopen(scans_by_folder, context=ctx)
scans = json.loads(f.read())["scans"]
if scans is None:
    print "[WW] There are no scan results in the folder ``{}''".format(args.scanfolder[0])
    sys.exit(-1)
if args.debug:
    print "[D] Got %i scans in folder %i" % (len(scans), folderid)

for s in scans:
    if args.debug:
        print "[D] Exporting %s" % s['name']
    data = json.dumps({'format': args.format})
    request = urllib2.Request(args.url + "/scans/%i/export" % s["id"], data,
                              {'Content-Type': 'application/json',
                               'X-Cookie': 'token=' + str(token)})
    f = urllib2.urlopen(request, context=ctx)
    fileref = scans = json.loads(f.read())["file"]
    if args.debug:
        print "[D] Got export file reference %s" % fileref
    attempt = 0
    while True:
        attempt += 1
        if args.debug:
            print "[D] Reqesting scan status for fileref %s, attempt %i" % (fileref, attempt)
        status_for_file = urllib2.Request(args.url + "/scans/%s/export/%s/status" % (
            s["id"], fileref), headers={'X-Cookie': 'token=' + str(token)})
        f = urllib2.urlopen(status_for_file, context=ctx)
        status = json.loads(f.read())["status"]
        if status == "ready":
            download = urllib2.Request(args.url + "/scans/%s/export/%s/download?token=%s" % (s["id"], fileref, token),
                                       headers={'X-Cookie': 'token=' + str(token)})
            f = urllib2.urlopen(download, context=ctx)
            print "[**] Downloaded report for %s" % s["name"]
            with open(os.path.join(OUTPUDIR, "{}.{}".format(s["name"], args.format)), "wb") as rep:
                rep.write(f.read())
            break
        else:
            if args.debug:
                print "[D] Sleeping for %i seconds..." % SLEEP
            time.sleep(args.sleep)

