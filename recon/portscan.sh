#!/bin/bash

# Help menu
show_help() {
  cat <<EOF
Usage: $0 <file_path> [--naabu]

Arguments:
  file_path      Path to the subdomain list to resolve IPs

Options:
  -h, --help         Show this help message and exit
  -n, --naabu        Run naabu + httpx after translating domains
EOF
}

# Translate domains to unique IPs
ip_translation_for_naabu() {
  input="$1"
  output="ips_for_naabu.txt"
  temp_output="temp_output_naabu.txt"

  if [ ! -f "$input" ]; then
    echo -e "\e[31mFile not found: $input\e[0m"
    show_help
    exit 0
  fi

  echo -e "\e[33mTranslating domains to IPs\e[0m"

  > "$temp_output"  # Clear file before appending
  while IFS= read -r domain; do
    ip=$(nslookup "$domain" | awk '/^Address: / { print $2; exit }')
    [ -n "$ip" ] && echo "$ip" >> "$temp_output"
  done < "$input"

  sort -u "$temp_output" > "$output"
  echo -e "\e[32mOutput written to: $output\e[0m"

  rm -f "$temp_output"
}

# Run only httpx directly on resolved IPs
run_httpx_direct() {
  scan_input="ips_for_naabu.txt"
  if [ ! -s "$scan_input" ]; then
    echo -e "\e[31mNo IPs found in $scan_input, skipping httpx.\e[0m"
    exit 0
  fi

  echo -e "\e[33mRunning httpx directly on IPs since no arguments...\e[0m"
  httpx -silent -l "$scan_input" -title | tee http_ips.txt
}

# Run naabu and then httpx
run_naabu_func() {
  scan_input="ips_for_naabu.txt"
  if [ ! -s "$scan_input" ]; then
    echo -e "\e[31mNo IPs found in $scan_input, skipping naabu.\e[0m"
    exit 0
  fi

  echo -e "\e[33mRunning naabu...\e[0m"
  naabu -list "$scan_input" -o scan-result_of_IPs.txt

  if [ -s scan-result_of_IPs.txt ]; then
    echo -e "\e[33mRunning httpx on naabu results...\e[0m"
    httpx -silent -l scan-result_of_IPs.txt -title -o httpx_naabu.txt
  else
    echo -e "\e[33mNo open ports found. Running httpx on original IPs...\e[0m"
    httpx -silent -l "$scan_input" -title -o http_ips.txt
  fi
}

# ---- Main Logic ----
main() {
  if [[ "$1" == "-h" || "$1" == "--help" || -z "$1" ]]; then
    show_help
    exit 0
  fi

  echo -e "\e[33mStarting the ip_translation process\e[0m"
  ip_translation_for_naabu "$1"

  shift
  if [[ "$1" == "--naabu" ]]; then
    run_naabu_func
  else
    run_httpx_direct
  fi
}

main "$@"

