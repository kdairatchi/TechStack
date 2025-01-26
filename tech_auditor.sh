#!/bin/bash

# TechStack Auditor v1.0
# Combines technology detection with CVE analysis
# Dependencies: npm, wappalyzer, builtwith (API key), jq, curl, nuclei, cve_searchsploit

TARGET="$1"
BUILTWITH_API_KEY="your_builtwith_api_key"  # Get from https://builtwith.com
NVD_API_KEY="your_nvd_api_key"             # Get from https://nvd.nist.gov/developers

# Install required dependencies
check_dependencies() {
    command -v npm >/dev/null 2>&1 || { echo >&2 "npm required. Install nodejs."; exit 1; }
    command -v jq >/dev/null 2>&1 || { echo >&2 "jq required. Install via package manager."; exit 1; }
    command -v nuclei >/dev/null 2>&1 || { echo >&2 "nuclei required. Install via 'go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest'"; exit 1; }
    
    # Check Wappalyzer
    if ! command -v wappalyzer &> /dev/null; then
        echo "Installing Wappalyzer..."
        npm install -g wappalyzer
    fi
}

run_wappalyzer() {
    echo -e "\n\033[1;34m[+] Running Wappalyzer analysis...\033[0m"
    wappalyzer -r $TARGET | jq '.technologies[] | {name: .name, version: .version}' > wappalyzer_results.json
}

run_builtwith() {
    echo -e "\n\033[1;34m[+] Querying BuiltWith API...\033[0m"
    curl -s "https://api.builtwith.com/v20/api.json?KEY=$BUILTWITH_API_KEY&LOOKUP=$TARGET" \
        | jq '[.Results[].Result.Paths[].Technologies[] | {name: .Name, version: .Version}]' > builtwith_results.json
}

merge_results() {
    echo -e "\n\033[1;34m[+] Merging technology data...\033[0m"
    jq -s 'add' wappalyzer_results.json builtwith_results.json | jq 'group_by(.name) | map(.[0])' > merged_tech.json
    echo "Detected technologies:"
    jq -r '.[] | "\(.name) \(.version // "unknown")"' merged_tech.json | column -t
}

query_cves() {
    echo -e "\n\033[1;34m[+] Checking for CVEs...\033[0m"
    mkdir -p cve_reports
    
    jq -c '.[]' merged_tech.json | while read tech; do
        name=$(echo $tech | jq -r '.name')
        version=$(echo $tech | jq -r '.version')
        
        if [ "$version" != "unknown" ]; then
            echo "Checking $name $version..."
            
            # Query NVD API
            curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$name $version" \
                -H "apiKey: $NVD_API_KEY" -o "cve_reports/${name}_nvd.json"
            
            # Search Exploit-DB
            searchsploit -j "$name $version" > "cve_reports/${name}_exploitdb.json"
            
            # Check Nuclei templates
            nuclei -silent -nt -ts severity:high,medium -t ~/nuclei-templates/ -u $TARGET | grep -i "$name" > "cve_reports/${name}_nuclei.txt"
        fi
    done
}

generate_report() {
    echo -e "\n\033[1;34m[+] Generating final report...\033[0m"
    echo "# Technology Audit Report for $TARGET" > report.md
    echo "## Detected Technologies" >> report.md
    jq -r '.[] | "- \(.name) \(.version // "unknown")"' merged_tech.json >> report.md
    
    echo -e "\n## Vulnerability Findings" >> report.md
    for file in cve_reports/*; do
        tech_name=$(basename $file | cut -d'_' -f1)
        echo -e "\n### $tech_name" >> report.md
        
        # Process NVD results
        if [ -f "cve_reports/${tech_name}_nvd.json" ]; then
            cve_count=$(jq '.totalResults' "cve_reports/${tech_name}_nvd.json")
            echo "**NVD CVEs ($cve_count):**" >> report.md
            jq -r '.vulnerabilities[].cve.id' "cve_reports/${tech_name}_nvd.json" | head -5 >> report.md
        fi
        
        # Process Exploit-DB results
        if [ -f "cve_reports/${tech_name}_exploitdb.json" ]; then
            exploit_count=$(jq '.RESULTS_EXPLOIT' "cve_reports/${tech_name}_exploitdb.json")
            echo -e "\n**Exploit-DB Entries ($exploit_count):**" >> report.md
            jq -r '.RESULTS_EXPLOIT[].Path' "cve_reports/${tech_name}_exploitdb.json" | head -3 >> report.md
        fi
        
        # Add Nuclei findings
        if [ -f "cve_reports/${tech_name}_nuclei.txt" ]; then
            echo -e "\n**Nuclei Findings:**" >> report.md
            head -3 "cve_reports/${tech_name}_nuclei.txt" >> report.md
        fi
    done
    
    echo -e "\n\033[1;32m[+] Report generated: report.md\033[0m"
}

main() {
    check_dependencies
    run_wappalyzer
    run_builtwith
    merge_results
    query_cves
    generate_report
}

if [ -z "$1" ]; then
    echo "Usage: $0 <target-domain>"
    exit 1
fi

main
