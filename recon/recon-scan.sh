#!/bin/bash
: '
Module Name: AutoRecon
Author: Olof Magnusson, Zagros Bingöl
Date: 2025-06-08
Version: 1

A tool that automate the reconnaissance process and format data in a organizeed fashion.
'

show_help() {
  cat << EOF
Usage: $0 <pentesterid> <target> <scope>"

Arguments:
  pentester_id        Numeric or string ID to identify who is running the scan
  target              The domain name to scan (e.g., example.com)" 
  scope               Scope name or identifier (e.g, api, full, limited)"

Options:
  -h, --help  Show this help message and exit
EOF
}

# To provide fast help utility to the user
if [[ "$1" == -h || "$1" == --help ]]; then
  show_help
  exit 1
fi

# Check valid passed arguments
check_correct_args_pass() {
  if [[ -z "$1"  ||  -z "$2" || -z "$3" ]]; then
    show_help
    exit 1
  fi
}

print_figlet() {
    message="$1"
    if command -v figlet > /dev/null 2>&1; then
        figlet "$message"
    else
        echo "==== $message ===="
    fi
}

# Scan banner
print_welcome_banner() {
  print_figlet "Program initiated"
  echo "============================"
  echo "Starting the program..."
  echo "============================"
}

print_scanner_initiated() {
  print_figlet "Scanning initiated"
  echo "============================"
  echo -e "\e[33mLoading API-keys...\e[0m"
  echo "============================"
}

print_scanner_started() {
  print_figlet "Scanning started"
  echo "============================"
  echo -e "\e[33mStarting the scan process...\e[0m"
  echo "============================"
}

# Initializer block 
initialize() {
  id="$1"
  target="$2"
  scope="$3"
  scope_path="$scan_path/scope/$scope"
  ppath="$(pwd)"
  timestamp=$(date +'%H:%M:%S')
  scan_path="$HOME/auto-recon/recon/scan-$target-$(date +%F)"
}

print_out_initalization() {
  cat << EOF
Pentest ID: $id
Target: $target
Scope: $scope
Current Path: $ppath
Scope Path: $scope_path
Timestamp: $timestamp
Scan Path: $scan_path
Issuer: $USER
EOF
}

# Check if a path exist before creating a scope and path - if there is a repetitive scan.
check_path_existence() {
  if [ ! -d "$scan_path" ]; then
    echo -e "\e[33mCreating scan path......\e[0m"
    mkdir -p "$scan_path" && echo -e "\e[32mDirectory created: $scan_path\e[0m"
    return 0
  else
    echo -e "\e[34m Scan path already exist: $scan_path\e[0m"
    return 1
  fi
}

# Check first that we are in correct path when executing script
check_current_path() {
  required_path="$scan_path"
  if [ "$(pwd)" != "$required_path" ]; then
    echo -e "\e[33mMoving into the scan directory\e[0m"
    cd "$scan_path" || echo -e "\e[31mFailed to change directory to $scan_path\e[0m"
    return 0
  else
    echo -e "\e[31mCould not move to the scan directory\e[0m"
    return 1
  fi
}

# Functions to check/initalize API-keys 
check_if_api_key_exist() {
  # Check if the API key file exists
  if [ -r "$API_KEY_FILE" ]; then
    API_KEY=$(cat "$API_KEY_FILE")
    return 0
  else
    echo -e "\e[31mApi key not found. Please check path $API_KEY_FILE or your internet connection!\e[0m"
    return 1
  fi
}

initialize_api() {
  tool_name="$1"
  command="$2"
  api_key_file="$HOME/Projects/auto-recon/api_keys/${tool_name}.txt"

  API_KEY_FILE="$api_key_file"
  API_COMMAND="$command"

  check_if_api_key_exist

  echo -e "\e[32m${tool_name^} API key initialized\e[0m"
}

# Function to correct list of IP-addresses when iterating naabu
ip_translation_for_naabu() {

  # Define the file path
  input="$scan_path/enumerated_allsubdomains.txt"
  output="ips_for_naabu.txt"
  touch "temp_output_naabu.txt"
  temp_output="temp_output_naabu.txt"

  while IFS= read -r domain; do
    # This will return only unique IP-addresses from the scan so we do not miss anything from the original file
    ip=$(nslookup "$domain" | awk '/^Address: / { print $2; exit }')
    echo "$ip" >>"$temp_output"
  done <"$input"

  echo $temp_output

  # Sort and filter unique IPs, then write to the output file
  sort -u "$temp_output" >"$output"
  echo "Tmpfile sorted"
  # Remove the temporary file
  rm $temp_output
}

# Check for easier dev domain filtering
check_if_dev_domain() {
  if [ -s "$scan_path/enumerated_devdomains.txt" ]; then
    echo -e "\e[32mDev domains found! Development domains saved to the $scan_path/enumerated_devdomains.txt\e[0m"
    cat "$scan_path/enumerated_devdomains.txt" | httpx -probe -sc -title -fhr -location -wc -sc -cl -ct -web-server -asn -o "$scan_path/httpx-out-devdomains.txt" -p 8000,8080,8443,443,80,8008,3000,5000 -t 75
    return 0
  else
    return 1
  fi
}

# Make sure that the user passes an argument when executing the script.
check_correct_args_pass "$1" "$2" "$3"

# Initialize all necessary objects
initialize "$1" "$2" "$3"

#Printout all the initialized variables
print_out_initalization

# Double check that scan path gets corrected created.
check_path_existence 

#Check so that we are in correct path when executing the script.
check_current_path

print_welcome_banner
sleep 2

# ---- Main Logic ----
main() {

  # Initalize API-keys
  initialize_api "httpx" "httpx"
  initialize_api "shodan" "shodan init"

  # Here we start the actual scan
  echo -e "\e[32mInitalization done. Starting the scan\e[0m"
  print_scanner_started

  echo -e "\e[33mStarting enumerating subdomains using shodan\e[0m"
  shodan domain "$target" | awk 'NR>2 && $1!="" { print $1 }'| sed "s/$/.$target/" >"$scan_path/enumerated_subdomains_shodan.txt"

  echo -e "\e[33mStarting enumerating subdomains using assetfinder\e[0m"
  assetfinder -subs-only "$target" | tee "$scan_path/enumerated_subdomains_assetfinder.txt"

  echo -e "\e[33mStarting enumerating subdomains using subfinder\e[0m"
  subfinder -all -d "$target" -o "$scan_path/enumerated_subdomains_subfinder.txt" -v

  echo -e "\e[33mStarting enumerating subdomains and intel using amass\e[0m"
  amass enum -d "$target" -o "$scan_path/enumerated_subdomains_amass.txt" 
  python3 $HOME/Projects/auto-recon/scripts/amass_host_extractor/amass_host_extractor.py -i "$scan_path/enumerated_subdomains_amass.txt" -o "$scan_path/enumerated_subdomains_amass_filtered.txt"
  amass intel -d "$target" -whois -o "$scan_path/enumerated_subdomains_amassintel.txt"

  # Add these two above enumerations type together
  cat "$scan_path/enumerated_subdomains_amass_filtered.txt" "$scan_path/enumerated_subdomains_amassintel.txt" > "$scan_path/enumerated_subdomains_all_amass.txt"

  # Merge all the domains identified from all the tools
  echo -e "\e[33mMerging all the domains found from the tools\e[0m"
  cat "$scan_path/enumerated_subdomains_subfinder.txt" "$scan_path/enumerated_subdomains_all_amass.txt" "$scan_path/enumerated_subdomains_shodan.txt" "$scan_path/enumerated_subdomains_assetfinder" >"$scan_path/enumerated_merged_domains.txt"

  # Fetch unique values and avoid duplicates when all domains are correctly fetched
  cat "$scan_path/enumerated_merged_domains.txt" | uniq >"$scan_path/enumerated_allsubdomains.txt"
  echo -e "\e[32mDone with merging subdomains from all tools.\e[0m"

  # Enumerate ASN numbers
  echo -e "\e[33mStarting enumerating all ASN numbers for the merged domains\e[0m"
  python3 $HOME/Projects/auto-recon/scripts/asn_identifier/domain_process_as.py -l "$scan_path/enumerated_allsubdomains.txt" -t 75 -o "$scan_path/asn_getter.txt"

  echo -e "\e[33mChecking all domains probes for success\e[0m"
  # Fetch all the web applications listening to normal ports. Might need to add more ports as we move on
  cat "$scan_path/enumerated_allsubdomains.txt" | httpx -probe -sc -title -fhr -location -wc -sc -cl -ct -web-server -asn -o "$scan_path/allsubdomains-httpx-out.txt" -p 8000,8080,8443,443,80,8008,3000,5000 -t 75

  # Focus only on succesful domains (-t=threading so you might need to tweak this depending on workload and CPU)
  echo -e "\e[33mFiltering data that we only got succesfull response\e[0m"
  python3 $HOME/Projects/auto-recon/scripts/httpresponse_extractor/data_filtering.py -i "$scan_path/allsubdomains-httpx-out.txt" -t 75 -o "$scan_path/allsubdomains-httpx-out-filtered.txt"
  cat "$scan_path/enumerated_allsubdomains.txt" | httpx -silent -o "$scan_path/allsubdomains-httpx-out.txt-filtered.txt"

  # Enumerate all dev domains and save it in an appropriate file
  echo -e "\e[33mChecking if there are any dev domains\e[0m"
  cat "$scan_path/allsubdomains-httpx-out-filtered.txt" | grep -Ei "dev.|.\dev-portal|\.dev\|\.staging\|\.test\|\.local|internal|sandbox|org|net" >"$scan_path/enumerated_devdomains.txt"
  check_if_dev_domain

  # Check for domain-takeover
  subzy run --targets "$scan_path/allsubdomains-httpx-out-filtered.txt" --vuln --output "$scan_path/domain-takeover-vuln.txt"

  # Create screenshot for every subdomain for visualisation
  echo -e "\e[33mCreating screenshot for every subdomain\e[0m"
  cat "$scan_path/enumerated_allsubdomains.txt" | httpx -ss -system-chrome -fr 
  echo -e "\e[32mScreenshots done.\e[0m"

  echo -e "\e[33mPort-scanning data gathering started\e[0m"
  ip_translation_for_naabu
  echo -e "\e[32mPort-scanning data gathering done\e[0m"

  echo -e "\e[33m Preparing to create directories and move files...\e[0m"

  mkdir "$scan_path/domain-takeover"
  mv -f domain-takeover-vuln.txt "$scan_path/domain-takeover" 2>/dev/null || true

  mkdir "$scan_path/domains/"
  mv -f enumerated_* "$scan_path/domains" 2>/dev/null || true

  mkdir "$scan_path/httpx/"
  mv -f *-httpx-* "$scan_path/httpx/" 2>/dev/null || true

  mkdir "$scan_path/ASN/"
  mv -f asn_getter.txt "$scan_path/ASN/" 2>/dev/null || true
  
  mkdir "$scan_path/naabu/"
  mv -f ips_for_naabu.txt "$scan_path/naabu/" 2>/dev/null || true

  mv -f "$scan_path/output/screenshot" "$scan_path/screenshot/" 2>/dev/null || true

  echo -e "\e[33mDone with moving files. Please see result in respective folder for manual analysis: $scan_path/\e[0m"

  echo -e "\e[33mCleaning inititated\e[0m"
  find "$scan_path/" -maxdepth 1 -type f -name "*.txt" -print0 | xargs -0 rm
  find "$scan_path/" -maxdepth 1 -type d -name "output" -exec rm -r {} +
  echo -e "\e[32mCleaning done\e[0m"
}
main

