#!/usr/bin/env python3
# Modified from averagesecurityguy
# Props to him
# [https://github.com/averagesecurityguy/](https://github.com/averagesecurityguy/)
#
# Command-line parser taken from from below:
# by Konrads Smelkovs (https://github.com/truekonrads)
#
# merger.py
# based off: [http://cmikavac.net/2011/07/09/merging-multiple-nessus-scans-python-script/](http://cmikavac.net/2011/07/09/merging-multiple-nessus-scans-python-script/)
# by: mastahyeti
#
# Everything glued together by _sen

import re
import requests
import json
import time
import argparse
import os
import sys
import getpass
import xml.etree.ElementTree as etree

requests.packages.urllib3.disable_warnings()
verify = False

parser = argparse.ArgumentParser(
    description='Download Nessus results in bulk / Merge Nessus files. All files are read from and written to the current working directory.')
parser.add_argument('--url', type=str, default='localhost', help="URL to Nessus instance")
parser.add_argument('--upload', nargs='?', const=True, default=False,
                    help='Upload and import a .nessus file from the current directory. Optionally specify filename, e.g. --upload myfile.nessus. If --merge is also used, the merged output file is uploaded automatically and the specified filename is disregarded.')
parser.add_argument('--format', '-F', type=str, default="html", choices=['nessus', 'html'], help='Export format, defaults to html')
parser.add_argument('-m', '--merge', nargs='?', const=True, default=False,
                    help='Merge all .nessus files in the current directory. Optionally provide a report name, e.g. -m "Client A". If --folder is also set, folder name takes priority.')
parser.add_argument('-e', '--export', action='store_true', help='Export and download scan files to the current directory')
parser.add_argument('--folder', '-f', type=str, help='Scan folder ID', default=0)
parser.add_argument('--access', type=str, help='Nessus API Access Key', default=None)
parser.add_argument('--secret', type=str, help='Nessus API Secret Key', default=None)
parser.add_argument('--username', '-u', type=str, help='Nessus username (required for --upload on Nessus Professional)', default=None)
parser.add_argument('-l', '--test-api', action='store_true', help='List folders / Test API key')
args = parser.parse_args()


def build_url(resource):
    return f"https://{args.url}:8834{resource}"


def connect(method, resource, data=None, files=None):
    """
    Send a request to Nessus using API key authentication.
    For --upload, use upload() which handles session auth instead.
    """
    headers = {
        'X-ApiKeys': f'accessKey={args.access};secretKey={args.secret}',
        'content-type': 'application/json'
    }
    encoded = json.dumps(data) if data is not None else None

    if method == 'POST':
        r = requests.post(build_url(resource), data=encoded, headers=headers, verify=verify, files=files)
    elif method == 'PUT':
        r = requests.put(build_url(resource), data=encoded, headers=headers, verify=verify)
    elif method == 'DELETE':
        r = requests.delete(build_url(resource), data=encoded, headers=headers, verify=verify)
    else:
        r = requests.get(build_url(resource), params=data, headers=headers, verify=verify)

    if r.status_code != 200:
        print(r.json().get('error', 'Unknown error'))
        sys.exit(1)

    return r.content if 'download' in resource else r.json()


def get_session():
    """
    Authenticate with Nessus using username/password.
    Returns a requests.Session with:
      - X-Cookie: token=<session_token>     (auth)
      - X-API-Token: <UUID from nessus6.js> (CSRF guard — required for /scans/import)
    """
    username = args.username
    password = getpass.getpass(f"[*] Password for '{username}': ")

    print("[*] Authenticating with username/password..")
    login_response = requests.post(
        build_url("/session"),
        json={"username": username, "password": password},
        verify=False
    )
    login_response.raise_for_status()
    session_token = login_response.json().get("token")
    if not session_token:
        raise ValueError(f"[!] Login failed — no token in response: {login_response.json()}")
    print("[*] Session token obtained.")

    session = requests.Session()
    session.verify = False
    session.headers.update({"X-Cookie": f"token={session_token}"})

    # X-API-Token is a static CSRF UUID embedded in nessus6.js
    # Required for all mutating requests — connection reset without it
    print("[*] Fetching X-API-Token..")
    js_response = session.get(build_url("/nessus6.js"), verify=False)
    js_response.raise_for_status()

    match = re.search(r'key:"getApiToken",value:function\(\)\{return"([^"]+)"', js_response.text)
    if not match:
        match = re.search(r'"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"', js_response.text)
    if not match:
        raise ValueError("[!] Could not extract X-API-Token from nessus6.js")

    session.headers.update({"X-API-Token": match.group(1)})
    print("[*] Session ready.")
    return session


def resolve_folder_name():
    """
    Look up the folder name for args.folder via the API.
    Returns the folder name string, or None if not found.
    Called only when API keys and folder ID are confirmed available.
    """
    try:
        folders = connect('GET', '/folders')
        return next(
            (f['name'] for f in folders.get('folders', []) if str(f['id']) == str(args.folder)),
            None
        )
    except Exception:
        return None


def get_merge_name():
    """
    Resolve the merged report name in priority order:
      1. Folder name looked up via API (if --folder and API keys are available)
      2. Value passed directly to -m flag
      3. Fallback: 'Merged Report'
    Format: '{NAME} - MERGED'

    If both a resolved folder name and an explicit -m value are supplied,
    the user is prompted to confirm which to use.
    """
    merge_arg = args.merge  # True if bare -m, str if -m "some name"
    folder_name = None

    if args.folder and args.access and args.secret:
        folder_name = resolve_folder_name()
        if not folder_name:
            print(f"[!] Warning: Could not resolve folder name for folder ID '{args.folder}'. Falling back to -m value or default.")

    # Conflict: folder resolved AND explicit -m name supplied — folder takes priority, but confirm
    if folder_name and isinstance(merge_arg, str):
        print(f"[!] Both --folder (resolves to '{folder_name}') and -m '{merge_arg}' were supplied.")
        choice = input(f"[?] Use folder name '{folder_name} - MERGED' as report name? [Y/N]: ").strip().lower()
        if choice != 'y':
            print("[*] Aborting. Re-run with only one of --folder or a -m name value.")
            sys.exit(0)

    if folder_name:
        return f"{folder_name} - MERGED"

    if isinstance(merge_arg, str):
        return f"{merge_arg} - MERGED"

    return "Merged Report - MERGED"


def upload():
    """
    Upload and import the file specified by args.upload into Nessus.

    Requires username/password auth — POST /scans/import is blocked by Nessus
    Professional when using API keys. Session-based auth replicates the browser flow.
    """
    file_name = args.upload

    try:
        session = get_session()

        print(f"[*] Uploading {file_name}..")
        with open(file_name, "rb") as f:
            files = {"Filedata": (os.path.basename(file_name), f, "text/xml")}
            upload_response = session.post(
                build_url("/file/upload"),
                params={"no_enc": 1},
                files=files
            )
        upload_response.raise_for_status()

        uploaded_filename = upload_response.json().get("fileuploaded")
        if not uploaded_filename:
            print(f"[!] Upload failed. Response: {upload_response.json()}")
            return
        print(f"[*] File uploaded as: {uploaded_filename}")

        print("[*] Importing scan into Nessus..")
        import_payload = {"file": uploaded_filename}
        if args.folder:
            import_payload["folder_id"] = int(args.folder)

        session.headers.update({"Content-Type": "application/json"})
        import_response = session.post(build_url("/scans/import"), json=import_payload)
        import_response.raise_for_status()
        print(f"[*] Import successful: {import_response.json()}")

    except FileNotFoundError:
        print(f"[!] Error: File not found: {file_name}")
    except requests.exceptions.HTTPError as e:
        print(f"[!] HTTP error: {e.response.status_code} — {e.response.text}")
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Connection error: {e}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")


def get_scans():
    """Get scans from a specific folder."""
    data = connect('GET', f'/scans?folder_id={args.folder}')
    scans_to_export = {s['id']: str(s['name']) for s in data['scans']}
    print(json.dumps(scans_to_export, indent=4))
    return scans_to_export


def export_status(sid, fid):
    """Returns True when the export is ready for download."""
    data = connect('GET', f'/scans/{sid}/export/{fid}/status')
    return data['status'] == 'ready'


def export(scans):
    """Export and download scan results to the current directory."""
    params = {'format': args.format, 'chapters': 'vuln_by_host'}

    for scan_id, scan_name in scans.items():
        print(f"Exporting {scan_name}")
        data = connect('POST', f'/scans/{scan_id}/export', data=params)
        file_id = data['file']

        while not export_status(scan_id, file_id):
            time.sleep(5)

        print(f"Downloading {scan_name}")
        data = connect('GET', f'/scans/{scan_id}/export/{file_id}/download')

        out_name = f"{scan_name}.{args.format}".replace('/', '_')
        duplicate = 0
        while out_name in os.listdir('.'):
            print("Duplicate scan name!")
            duplicate += 1
            out_name = f"{scan_name}_{duplicate}.{args.format}".replace('/', '_')

        print(f"Saving scan results to {out_name}.")
        with open(out_name, 'wb') as f:
            f.write(data)

    print("All downloads complete! hax0r")


def merge():
    """
    Merge all .nessus files in the current directory into a single file.
    Sets args.upload to the output filename if --upload is also active.
    """
    report_name = get_merge_name()
    out_filename = report_name + ".nessus"

    print(f"[*] Report name: '{report_name}'")

    mainTree = None
    report = None

    for fileName in os.listdir('.'):
        if not fileName.endswith(".nessus") or fileName == out_filename:
            continue

        print(f":: Parsing {fileName}")

        if mainTree is None:
            mainTree = etree.parse(fileName)
            report = mainTree.find('Report')
            report.attrib['name'] = report_name
        else:
            tree = etree.parse(fileName)
            for host in tree.findall('.//ReportHost'):
                existing_host = report.find(f".//ReportHost[@name='{host.attrib['name']}']")
                if not existing_host:
                    print(f"  adding host: {host.attrib['name']}")
                    report.append(host)
                else:
                    for item in host.findall('ReportItem'):
                        if not existing_host.find(f"ReportItem[@port='{item.attrib['port']}'][@pluginID='{item.attrib['pluginID']}']"):
                            print(f"  adding finding: {item.attrib['port']}:{item.attrib['pluginID']}")
                            existing_host.append(item)
        print(":: => done.")

    if mainTree is None:
        print("[!] No .nessus files found in current directory.")
        return

    with open(out_filename, 'wb') as merged_file:
        mainTree.write(merged_file, encoding="utf-8", xml_declaration=True)

    print(f"[*] All .nessus files merged to '{out_filename}'")

    # Hand off to upload() by setting args.upload to the output filename
    if args.upload:
        args.upload = out_filename


if __name__ == '__main__':
    if args.export or args.merge or args.upload:

        if args.export:
            if not (args.access and args.secret):
                print("[!] --export requires --access and --secret API keys.")
                sys.exit(1)
            print("Getting scan list....")
            scans = get_scans()
            print('Downloading and Exporting Scans...')
            export(scans)

        if args.merge:
            merge()  # sets args.upload if --upload is also active

        if args.upload:
            if not args.username:
                print("[!] --upload requires --username/-u.")
                print("[!] POST /scans/import is blocked for API key auth on Nessus Professional.")
                sys.exit(1)
            if args.upload is True:
                print("[!] --upload requires a filename, e.g. --upload myfile.nessus")
                print("[!] Or use --merge together with --upload to upload the merged output automatically.")
                sys.exit(1)
            upload()

    elif args.test_api:
        if not (args.access and args.secret):
            print("[!] --test-api requires --access and --secret API keys.")
            sys.exit(1)
        print(json.dumps(connect('GET', '/folders'), indent=4))

    else:
        print(parser.format_usage())