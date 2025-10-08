#!/usr/bin/env bash
set -euo pipefail

# -----------------------------
# scan_cvut_cams.sh
# Purpose: passive+active web scan for camera/media endpoints for cvut.cz (non-destructive)
# Usage: ./scan_cvut_cams.sh
# Requirements: subfinder, httpx, dnsx (optional), curl, jq, ffmpeg/ffprobe (optional), timeout, parallel (optional)
# -----------------------------

DOMAIN="cvut.cz"
OUTDIR="./scan_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"
WORDLIST="/mnt/data/subdomains_top500.txt"   # change if needed

# Safety / polite defaults
HTTPX_PORTS="80,443,8000,8080,8443,9000"
CURL_TIMEOUT=6
SLEEP_BETWEEN_REQUESTS=0.25   # gentle delay to avoid hammering hosts
MAX_PARALLEL=6               # for parallel jobs (if used)

echo "[*] Output directory: $OUTDIR"
mkdir -p "$OUTDIR"
cd "$OUTDIR"

# 0) Record metadata / consent note
cat > scan_info.txt <<EOF
Scan target: $DOMAIN
Date: $(date -u +"%Y-%m-%d %H:%M:%SZ")
Note: Non-destructive web-based reconnaissance only. Performed with user's stated permission for CTU Intro to Cybersecurity course.
Tools: subfinder, httpx, dnsx, curl, jq, ffprobe (optional)
EOF

# 1) Passive subdomain discovery (subfinder)
echo "[*] Running passive subdomain discovery (subfinder) for $DOMAIN..."
if command -v subfinder >/dev/null 2>&1; then
  subfinder -d "$DOMAIN" -silent > subs_passive.txt || true
  echo "[*] passive results: $(wc -l < subs_passive.txt) entries"
else
  echo "[!] subfinder not found, skipping passive discovery. Install via 'go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'"
  touch subs_passive.txt
fi

# 2) Optional brute-force using wordlist (gobuster/dnsx/gobuster recommended)
echo "[*] Running brute-force DNS discovery using WORDLIST (if dnsx available)..."
if command -v dnsx >/dev/null 2>&1; then
  # dnsx supports resolving names from wordlist with domain suffix
  # build candidate list from wordlist (only first 10000 to be safe)
  head -n 20000 "$WORDLIST" 2>/dev/null | sed "s/\$/.$DOMAIN/" > wf_candidates.txt || true
  dnsx -silent -resp -a -retry 1 -l wf_candidates.txt -o brute_dnsx.txt || true
  awk '{print $1}' brute_dnsx.txt | sort -u > subs_brute.txt || true
  echo "[*] brute results (dnsx): $(wc -l < subs_brute.txt || echo 0)"
else
  echo "[!] dnsx not found, skipping brute-force DNS. You can use gobuster dns instead."
  touch subs_brute.txt
fi

# 3) Merge and uniq subdomains
echo "[*] Merging passive + brute results..."
cat subs_passive.txt subs_brute.txt | sed '/^\s*$/d' | sort -u > subs_all.txt
echo "[*] Total unique subdomains: $(wc -l < subs_all.txt)"

# 4) HTTP probe (which subdomains have web UI)
echo "[*] Probing web services with httpx on ports: $HTTPX_PORTS ..."
if command -v httpx >/dev/null 2>&1; then
  cat subs_all.txt | httpx -ports "$HTTPX_PORTS" -silent -status-code -title -o subs_httpx.txt || true
  # normalize output: keep only scheme://host[:port]
  awk '{print $1}' subs_httpx.txt | sort -u > subs_http_hosts.txt || true
  echo "[*] Hosts with HTTP(S) detected: $(wc -l < subs_http_hosts.txt)"
else
  echo "[!] httpx not found. Trying simple curl probe for default ports 80/443..."
  cat subs_all.txt | while read -r s; do
    for p in 80 443 8080 8000 8443; do
      scheme="http"; [ "$p" -eq 443 ] && scheme="https"
      url="${scheme}://$s:$p"
      if curl -s --max-time 3 -I "$url" >/dev/null 2>&1; then
        echo "$url"
        break
      fi
    done
  done | sort -u > subs_http_hosts.txt || true
  touch subs_httpx.txt
fi

# 5) Fetch index pages and grep for common camera/media patterns
echo "[*] Fetching pages and searching for camera/media patterns..."
patterns="rtsp:|m3u8|snapshot|videostream|mjpeg|mjpg|axis-cgi|onvif|/snapshot|/image|/cgi-bin|/stream|live.m3u8|/streams/|/streaming/|/video.cgi|/videostream.cgi"
> pages_with_media_hits.txt
mkdir -p raw_pages

while read -r host; do
  # gentle delay
  sleep "$SLEEP_BETWEEN_REQUESTS"
  echo "[*] Checking $host"
  # try fetch with curl (follow redirects)
  curl -sL --max-time $CURL_TIMEOUT "$host" -o "raw_pages/$(echo "$host" | sed 's/[:\/]/_/g').html" || continue
  if grep -Eiq "$patterns" "raw_pages/$(echo "$host" | sed 's/[:\/]/_/g').html"; then
    echo "$host" >> pages_with_media_hits.txt
    echo "[+] Media indicators found on: $host"
  fi
done < subs_http_hosts.txt

echo "[*] Hosts with media-like content: $(wc -l < pages_with_media_hits.txt || echo 0)"

# 6) Test common camera endpoints for each http host (non-destructive)
echo "[*] Testing common camera endpoints (safe checks)..."
mkdir -p endpoints_results snapshots
common_paths=(
  "snapshot.jpg" "image.jpg" "jpg/image.jpg" "videostream.cgi" "video.cgi"
  "axis-cgi/mjpg/video.cgi" "onvif/device_service" "live.m3u8" "streams/1"
  "stream1" "stream" "media/live" "streaming/channels/101" "record/current"
)

> endpoints_results.txt
while read -r host; do
  for p in "${common_paths[@]}"; do
    url="${host%/}/$p"
    # gentle probe: only header request first
    sleep "$SLEEP_BETWEEN_REQUESTS"
    status_line=$(curl -sI --max-time $CURL_TIMEOUT -L -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
    echo "$status_line $url" >> endpoints_results.txt
    # if it looks promising (200 and common image/media ext), try to fetch small body
    if [[ "$status_line" =~ ^2 ]]; then
      # only download small content (max 100k)
      curl -s --max-time $CURL_TIMEOUT --connect-timeout 4 --range 0-100000 "$url" -o "snapshots/$(echo "$host" | sed 's/[:\/]/_/g')__$(echo "$p" | sed 's/\/+/_/g').bin" || true
      # check if file is an image/video by 'file'
      if command -v file >/dev/null 2>&1; then
        ftype=$(file -b "snapshots/$(echo "$host" | sed 's/[:\/]/_/g')__$(echo "$p" | sed 's/\/+/_/g').bin" || true)
        echo "    -> saved, type: $ftype"
      fi
    fi
  done
done < subs_http_hosts.txt

echo "[*] Endpoint tests done. Results: $OUTDIR/endpoints_results.txt"

# 7) Optional: if ffprobe exists, try probe any discovered m3u8/rtsp URLs from pages (non-destructive)
if command -v ffprobe >/dev/null 2>&1; then
  echo "[*] ffprobe present. Scanning saved pages for m3u8/rtsp and probing them (read-only probe)..."
  grep -Eoi 'https?://[^"'\'' ]+\.m3u8|rtsp://[^"'\'' ]+' raw_pages/* | sort -u > discovered_streams.txt || true
  > stream_probe_results.txt
  while read -r s; do
    [ -z "$s" ] && continue
    echo "[*] Probing: $s"
    # do a lightweight ffprobe (no download), timeout to avoid hangs
    timeout 8 ffprobe -v error -show_entries format=duration -of default=nw=1 "$s" > /dev/null 2>&1 && echo "OK $s" >> stream_probe_results.txt || echo "FAIL $s" >> stream_probe_results.txt
    sleep 0.5
  done < discovered_streams.txt || true
  echo "[*] Stream probe done. Results: stream_probe_results.txt"
else
  echo "[*] ffprobe not installed, skipping RTSP/HLS probing."
fi

# 8) Summarize results
echo "---- SUMMARY ----" > summary.txt
echo "scanned domain: $DOMAIN" >> summary.txt
echo "subdomains total: $(wc -l < subs_all.txt || echo 0)" >> summary.txt
echo "http hosts: $(wc -l < subs_http_hosts.txt || echo 0)" >> summary.txt
echo "hosts with media indicators: $(wc -l < pages_with_media_hits.txt || echo 0)" >> summary.txt
echo "endpoints results saved: $(realpath endpoints_results.txt)" >> summary.txt
if [ -f discovered_streams.txt ]; then
  echo "discovered streams: $(wc -l < discovered_streams.txt)" >> summary.txt
fi
echo "raw pages saved: $(realpath raw_pages)" >> summary.txt
echo "snapshots saved: $(realpath snapshots)" >> summary.txt

echo "[*] Done. Check the output folder: $OUTDIR"
echo "Please review summary.txt and evidence files. Keep test non-destructive and share results with instructor."

# end
