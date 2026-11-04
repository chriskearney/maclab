#!/usr/bin/env bash
# A smoke test of the labd image as Kubernetes runs it, on an empty data
# volume, behind a proxy at a public URL: https://maclab.chonkbase.net (its
# own host), or a prefix on a shared host such as https://chonkbase.net/maclab.
# A helper container on a private network plays the ingress controller (a
# trusted proxy sending X-Forwarded-Proto/Host). Nothing is pushed; no
# registry, cluster, credential or lab Mac is involved.
#
#   .github/scripts/image-smoke.sh <image> [public URL]
set -euo pipefail

IMG=${1:?usage: image-smoke.sh <image> [public URL]}
PUB=${2:-https://maclab.chonkbase.net}
HOST=${PUB#https://}
HOST=${HOST%%/*}
PREFIX=${PUB#https://$HOST}
CURL_IMG=curlimages/curl:8.11.1
ID=maclab-smoke-$$
NET=$ID
LABD_IP=172.30.99.10
ROOT=http://$LABD_IP:7770
B=$ROOT$PREFIX                      # the pod as the ingress reaches it
FWD=(-H 'X-Forwarded-Proto: https' -H "X-Forwarded-Host: $HOST")

fail() { echo "FAIL: $*" >&2; exit 1; }
cleanup() {
	docker logs "$ID" >"${RUNNER_TEMP:-/tmp}/labd-smoke.log" 2>&1 || true
	docker rm -f "$ID" >/dev/null 2>&1 || true
	docker volume rm "$ID" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network create --subnet 172.30.99.0/24 "$NET" >/dev/null
docker volume create "$ID" >/dev/null
docker run -d --name "$ID" --network "$NET" --ip "$LABD_IP" \
	--read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
	-v "$ID":/data "$IMG" \
	--listen=0.0.0.0:7770 --allow-plain-http --data=/data \
	--public-url="$PUB" --trusted-proxy=172.30.99.0/24 --maintainer=ci >/dev/null

# c runs curl from the "ingress" (an address in the trusted range), stdin passed through.
c() { docker run --rm -i --network "$NET" "$CURL_IMG" -sS "$@"; }
code() { c -o /dev/null -w '%{http_code}' "$@"; }

for _ in $(seq 60); do
	[ "$(code "${FWD[@]}" "$B/healthz" 2>/dev/null || true)" = 200 ] && break
	sleep 1
done
[ "$(c "${FWD[@]}" "$B/healthz")" = ok ] || fail "healthz"

[ "$(docker exec "$ID" id -u)" = 10001 ] || fail "labd does not run as uid 10001"
TOK=$(docker exec "$ID" cat /data/admin.token)
echo "::add-mask::$TOK"
AUTH=(-H "Authorization: Bearer $TOK")

# The UI, under the prefix, with its <base> and headers.
page=$(c -D - "${FWD[@]}" "$B/")
grep -qF "<base href=\"$PREFIX/\">" <<<"$page" || fail "the UI's <base>"
grep -qi '^strict-transport-security: max-age=' <<<"$page" || fail "HSTS"
grep -qi "^content-security-policy: frame-ancestors 'none'" <<<"$page" || fail "frame-ancestors"
grep -qi '^x-content-type-options: nosniff' <<<"$page" || fail "nosniff"
[ "$(code "${FWD[@]}" "$B/ui/app.js")" = 200 ] || fail "app.js"

# The API: tokens only, under the prefix only.
[ "$(code "${FWD[@]}" "$B/api/devices")" = 401 ] || fail "the API without a token"
[ "$(c "${FWD[@]}" "${AUTH[@]}" "$B/api/devices")" = "[]" ] || fail "the API with the token"
if [ -n "$PREFIX" ]; then
	[ "$(code "${FWD[@]}" "${AUTH[@]}" "$ROOT/api/devices")" = 404 ] || fail "the API outside the prefix"
	[ "$(code "${FWD[@]}" "${AUTH[@]}" "${ROOT}${PREFIX}x/api/devices")" = 404 ] || fail "a sibling path"
	[ "$(code "${FWD[@]}" "${AUTH[@]}" "$B//api/devices")" = 404 ] || fail "a path the router would clean"
fi

# What the proxy forwards must name the public URL.
[ "$(code -H 'X-Forwarded-Proto: https' -H 'X-Forwarded-Host: evil.example' "${AUTH[@]}" "$B/api/devices")" = 421 ] || fail "another host forwarded"
[ "$(code -H 'X-Forwarded-Proto: http' -H "X-Forwarded-Host: $HOST" "${AUTH[@]}" "$B/api/devices")" = 421 ] || fail "plain http forwarded"

# A page from another origin can't change anything.
[ "$(code -X POST "${FWD[@]}" "${AUTH[@]}" -H 'Origin: https://evil.example' -d '{}' "$B/api/jobs")" = 403 ] || fail "a cross-origin POST"

# An invite: the one-liner, the terms and lab-agent, with the token in headers only.
inv=$(c -X POST "${FWD[@]}" "${AUTH[@]}" -H "Origin: https://$HOST" -d '{"name":"ci-mac"}' "$B/api/enroll-tokens")
ENR=$(jq -r .token <<<"$inv")
echo "::add-mask::$ENR"
cmd=$(jq -r .join_command <<<"$inv")
grep -qF "U='$PUB'" <<<"$cmd" || fail "the one-liner's URL"
grep -qF -- '-H @-' <<<"$cmd" || fail "the one-liner's header on stdin"
grep -qF -- '--token-stdin' <<<"$cmd" || fail "the one-liner's token on stdin"
want=$(docker exec "$ID" sha256sum /usr/local/bin/lab-agent-linux-arm64 | cut -d' ' -f1)
grep -qF "echo '$want  '" <<<"$cmd" || fail "the one-liner's lab-agent sha256"
got=$(printf 'Authorization: Bearer %s\n' "$ENR" | c "${FWD[@]}" -H @- "$B/api/join/lab-agent" | sha256sum | cut -d' ' -f1)
[ "$got" = "$want" ] || fail "the downloaded lab-agent"
terms=$(printf 'Authorization: Bearer %s\n' "$ENR" | c "${FWD[@]}" -H @- "$B/api/join/terms")
[ "$(jq -j '.text' <<<"$terms" | sha256sum | cut -d' ' -f1)" = "$(jq -r .sha256 <<<"$terms")" ] || fail "the terms' sha256"
[ "$(code "${FWD[@]}" "$B/api/join/terms?token=$ENR")" = 401 ] || fail "a token in the URL"

# labd's log holds neither token.
logs=$(docker logs "$ID" 2>&1)
grep -qF "$TOK" <<<"$logs" && fail "labd logged the Maintainer token"
grep -qF "$ENR" <<<"$logs" && fail "labd logged the enrollment token"
[ "$(docker inspect -f '{{.State.Running}}' "$ID")" = true ] || fail "labd stopped"
echo "image smoke at $PUB: PASS"
