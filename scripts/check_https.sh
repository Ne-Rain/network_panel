#!/usr/bin/env bash
# Run with Bash. Only makes a GET request; start the server separately.
set -euo pipefail

usage() {
    printf 'Usage: bash %s [HTTPS_URL [CA_CERT [EXPECTED_BODY]]]\n' "${0##*/}"
    printf 'Defaults: https://localhost:8443/hello, <project>/certs/server.crt, hello\n'
}

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
    usage
    exit 0
fi
if (( $# > 3 )); then
    usage >&2
    exit 2
fi

# Resolve the certificate from this script's location, not the caller's cwd.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd -- "$script_dir/.." && pwd)"
url="${1:-https://localhost:8443/hello}"
ca_cert="${2:-$project_dir/certs/server.crt}"
expected_body="${3-hello}"

if [[ $url != https://* ]]; then
    printf 'FAIL: URL must start with https://\n' >&2
    exit 2
fi
for dependency in curl mktemp cmp; do
    if ! command -v "$dependency" >/dev/null 2>&1; then
        printf 'FAIL: required command not found: %s\n' "$dependency" >&2
        exit 2
    fi
done
if [[ ! -f $ca_cert || ! -r $ca_cert ]]; then
    printf 'FAIL: certificate is not a readable file: %s\n' "$ca_cert" >&2
    exit 2
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/netpanel-https.XXXXXX")"
cleanup() { rm -rf -- "$work_dir"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf '%s' "$expected_body" > "$work_dir/expected.body"

# --disable is first to ignore .curlrc (which could contain insecure options).
# Keep certificate AND hostname verification enabled. Do not follow redirects
# or use a proxy for this LAN test. curl's exit code covers TLS/transport errors;
# the HTTP status and body are checked separately below.
if http_status="$(curl --disable \
    --silent --show-error \
    --http1.1 --proto '=https' --noproxy '*' \
    --connect-timeout 5 --max-time 15 \
    --cacert "$ca_cert" \
    --output "$work_dir/actual.body" \
    --write-out '%{http_code}' \
    "$url")"; then
    :
else
    curl_status=$?
    printf 'FAIL: HTTPS request failed (curl exit %s). See curl error above.\n' \
        "$curl_status" >&2
    exit 1
fi

if [[ $http_status != 200 ]]; then
    printf 'FAIL: expected HTTP 200, received HTTP %s\n' "$http_status" >&2
    exit 1
fi

# Compare the original files, not a shell variable: command substitution would
# strip trailing newlines and could incorrectly accept "hello\n" as "hello".
if ! cmp -s -- "$work_dir/expected.body" "$work_dir/actual.body"; then
    printf 'FAIL: HTTP 200 received, but the response body does not match exactly.\n' >&2
    exit 1
fi

printf 'PASS: certificate verified, HTTP 200, response body matched exactly.\n'
