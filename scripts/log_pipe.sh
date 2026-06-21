#!/bin/sh
set -eu

LOG_PATH=${LOG_PATH:-/opt/baresip/system.log}
LOG_MAX_BYTES=${LOG_MAX_BYTES:-20971520}
LOG_KEEP_BYTES=${LOG_KEEP_BYTES:-5242880}
line_count=0

trim_log() {
    [ -f "$LOG_PATH" ] || return 0
    size=$(wc -c < "$LOG_PATH")
    [ "$size" -le "$LOG_MAX_BYTES" ] && return 0

    tmp_path="${LOG_PATH}.trim.$$"
    tail -c "$LOG_KEEP_BYTES" "$LOG_PATH" | sed '1d' > "$tmp_path"
    cat "$tmp_path" > "$LOG_PATH"
    rm -f "$tmp_path"
}

mkdir -p "$(dirname "$LOG_PATH")"
touch "$LOG_PATH"
trim_log

while IFS= read -r line || [ -n "$line" ]; do
    printf '%s\n' "$line"
    printf '%s\n' "$line" >> "$LOG_PATH"
    line_count=$((line_count + 1))
    if [ "$line_count" -ge 100 ]; then
        trim_log
        line_count=0
    fi
done
