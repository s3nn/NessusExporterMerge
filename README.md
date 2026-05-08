# NessusExportMerge

A Python script for bulk-downloading, merging, and uploading Nessus scan results. Designed for **Nessus Professional**

Credits: built on top of work by [averagesecurityguy](https://github.com/averagesecurityguy/), [Konrads Smelkovs](https://github.com/truekonrads), and [mastahyeti](http://cmikavac.net/2011/07/09/merging-multiple-nessus-scans-python-script/).

***

## Features

- **Export** — bulk-download scan results from a Nessus folder (HTML or `.nessus` format)
- **Merge** — merge multiple `.nessus` files in the current directory into a single report
- **Upload** — upload and import a `.nessus` file back into Nessus Professional

> **Note:** All file operations read from and write to the **current working directory**. Run the script from the directory containing your `.nessus` files.

***

## Requirements

```
pip install requests
```

Python 3.6+

***

## Authentication

Two authentication modes are supported depending on the operation:

| Mode | Used for | Args |
|---|---|---|
| **API Keys** | `--export`, `--test-api` | `--access`, `--secret` |
| **Username / Password** | `--upload` | `--username` (password prompted securely) |

> **Why two modes?** Nessus Professional v10 blocks `POST /scans/import` when using API key authentication. The upload workflow replicates the browser session (using `X-Cookie` + `X-API-Token`) to work around this restriction.

***

## Full pipeline: export → merge → upload (local Nessus instance)

```bash
python nessus_exporter.py --access 'access' --secret 'secret' --folder 13 -F nessus -e -m --upload -u user

```

For remote, just specify `--url` option/

***

## Usage

### Export scans from a folder

Downloads all scans from the specified folder to the current directory.

```bash
python /path/to/nessus_exporter.py --export --folder 42 --access <accessKey> --secret <secretKey>
python /path/to/nessus_exporter.py --export --folder 42 --access <accessKey> --secret <secretKey> -F nessus
```

- Default format is `html`. Use `-F nessus` to download raw `.nessus` files.

***

### Merge `.nessus` files

Merges all `.nessus` files in the current directory into a single file.

```bash
# Auto-name from folder (requires API keys + --folder)
python /path/to/nessus_exporter.py -m --folder 42 --access <accessKey> --secret <secretKey>

# Explicit report name
python /path/to/nessus_exporter.py -m "Client A"

# Default name (outputs: 'Merged Report - MERGED.nessus')
python /path/to/nessus_exporter.py -m
```

Output filename format: `{NAME} - MERGED.nessus`

If both `--folder` and a `-m "name"` value are supplied, the folder name takes priority and you will be prompted to confirm.

***

### Upload and import a `.nessus` file

Uploads a `.nessus` file and imports it into a Nessus folder. Password is always prompted securely — it is never passed as a command-line argument.

```bash
# Upload a specific file
python /path/to/nessus_exporter.py --upload myfile.nessus --username admin --folder 42

# Upload and move to default folder (folder_id 0)
python /path/to/nessus_exporter.py --upload myfile.nessus --username admin
```

***

### Merge and upload in one step

```bash
python /path/to/nessus_exporter.py -m "Client A" --upload --username admin --folder 42
python /path/to/nessus_exporter.py -m --folder 42 --access <accessKey> --secret <secretKey> --upload --username admin
```

When `--merge` and `--upload` are used together, the merged output file is passed to `--upload` automatically — no need to specify a filename.

***

### Test API keys / list folders

```bash
python /path/to/nessus_exporter.py --test-api --access <accessKey> --secret <secretKey>
```

***

## All Options

```
usage: /path/to/nessus_exporter.py [--url URL] [--upload [FILE]] [--format {nessus,html}]
                 [-m [NAME]] [-e] [--folder ID]
                 [--access KEY] [--secret KEY]
                 [--username USER] [-l]

  --url URL             URL to Nessus instance (default: localhost)
  --upload [FILE]       Upload and import a .nessus file. Optionally specify
                        filename. If --merge is also used, merged output is
                        uploaded automatically.
  -F, --format          Export format: nessus or html (default: html)
  -m, --merge [NAME]    Merge all .nessus files in the current directory.
                        Optionally provide a report name, e.g. -m "Client A".
                        If --folder is also set, folder name takes priority.
  -e, --export          Export and download scan files to the current directory
  -f, --folder ID       Scan folder ID
  --access KEY          Nessus API Access Key
  --secret KEY          Nessus API Secret Key
  -u, --username USER   Nessus username (required for --upload)
  -l, --test-api        List folders / Test API key
  -k, --skip-tls        Skip SSL certificate verification (equivalent to
                        curl -k). Required for hosts with self-signed certs (e.g. localhost)
```


## Notes

- Run from current directory of where you your files will be exported or where they currently at.
- **Nessus Professional** This script is not designed for Tenable.io, Tenable.sc, or Nessus Manager — the upload workaround is specific to the local Nessus Pro API behaviour.
- **SSL verification is enabled by default**. For localhost or other hosts using self-signed certs, use `-k`. 
- **API keys are generated** under Nessus → Settings → My Account → API Keys.
- The `X-API-Token` CSRF token is extracted automatically from the Nessus JS bundle at runtime. If upload breaks after a Nessus version upgrade, this is the first thing to check.