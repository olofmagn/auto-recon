#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e 

# Hygiene
echo -e "\e[33mUpdating package lists...\e[0m"
apt-get update -y
apt-get upgrade -y

# Dependency install
echo -e "\e[33mInstalling system dependencies...\e[0m"
apt-get install -y figlet python3-shodan libpcap0.8-dev python3-pip golang-go

# Python packages
echo -e "\e[33mInstalling Python packages...\e[0m]"
pip3 install pandas bs4 ipwhois

# Go tools used in the script
echo -e "\e[33mInstalling Go tools...\e[0m"
go install -v github.com/PentestPad/subzy@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/owasp-amass/amass/v4/...@master
go install github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Printout succesful installation
echo -e "[\e32mAll dependencies installed successfully!\e[0m"
