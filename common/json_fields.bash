#!/usr/bin/env bash
# Shared JSON-string escaping for Bash audit fields (NUL cannot occur in Bash strings).
json_escape() {
    local value="$1" number character replacement
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    if [[ "$value" =~ [[:cntrl:]] ]]; then
      for ((number = 1; number < 32; number++)); do
        printf -v character '%b' "\\$(printf '%03o' "$number")"
        printf -v replacement '\\u%04x' "$number"
        value=${value//"$character"/"$replacement"}
      done
    fi
    printf '%s' "$value"
}
