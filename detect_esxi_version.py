import requests
import re
import argparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable SSL verification warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()

# Dictionary to store the extracted data (build number as key, release name as value)
build_number_dict = {}

def fetch_build_numbers():
    url = 'https://knowledge.broadcom.com/external/article/316595/build-numbers-and-versions-of-vmware-esx.html'
    response = requests.get(url)
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')
    tables = soup.find_all('table')
    
    for table in tables:
        headers = [th.get_text(strip=True) for th in table.find_all('td') if th.find('strong')]
        if 'Release Name' in headers and 'Build Number' in headers:
            release_name_index = headers.index('Release Name')
            build_number_index = headers.index('Build Number')
            
            for row in table.find_all('tr')[1:]:
                cells = row.find_all('td')
                if len(cells) > max(release_name_index, build_number_index):
                    release_name = cells[release_name_index].get_text(strip=True)
                    if cells[release_name_index].find('a'):
                        release_name = cells[release_name_index].find('a').get_text(strip=True)
                    build_number = cells[build_number_index].get_text(strip=True)
                    build_number_dict[build_number] = release_name

def send_soap_request(url):
    headers = {"Content-Type": "text/xml", "Host": url}
    payload = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <soap:Header>
      <operationID>00000001-00000001</operationID>
   </soap:Header>
   <soap:Body>
      <RetrieveServiceContent xmlns="urn:internalvim25">
         <_this xsi:type="ManagedObjectReference" type="ServiceInstance">ServiceInstance</_this>
      </RetrieveServiceContent>
   </soap:Body>
</soap:Envelope>"""
    try:
        response = requests.post(f"{url}/sdk/", headers=headers, data=payload, timeout=60, verify=False)
        if response.status_code == 200:
            return response.text
        #else:
        #    print(f"Received unexpected status code {response.status_code} for {url}")
    except requests.exceptions.RequestException as e:
        #print(f"Error occurred with {url}: {e}")
        pass
    return None

def extract_version_info(response_text, url):
    name_match = re.search(r"<name>(.*?)</name>", response_text)
    version_match = re.search(r"<version>(.*?)</version>", response_text)
    build_match = re.search(r"<build>(.*?)</build>", response_text)

    if name_match and version_match and build_match:
        name = name_match.group(1)
        version = version_match.group(1)
        build = build_match.group(1)
        release_name = build_number_dict.get(build, "Build number not found")
        if "ESXi " not in release_name:
            release_name = release_name.replace("ESXi", "ESXi ")
        print(f"{url}, (Release Name: {release_name}) (Version: {version}) (Build ID: {build})")
    else:
        print(f"Failed to extract version information from {url}.")

def process_url(url):
    response_text = send_soap_request(url)
    if response_text:
        extract_version_info(response_text, url)
    #else:
    #    print(url,response_text)

def main():
    parser = argparse.ArgumentParser(description="Detect VMware vCenter version information.")
    parser.add_argument("-u", "--url", help="The URL of the VMware vCenter server (e.g., https://172.29.216.3)", default=None)
    parser.add_argument("-f", "--file", help="File containing list of URLs to process", default=None)
    parser.add_argument("-n", "--threads", type=int, default=4, help="Number of concurrent threads (default: 4)")
    args = parser.parse_args()

    fetch_build_numbers()
    
    urls = []
    if args.url:
        urls.append(args.url)
    elif args.file:
        with open(args.file, 'r') as file:
            urls = [line.strip() for line in file.readlines() if line.strip()]
    else:
        print("Please provide either a URL or a file containing a list of URLs.")
        return
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        executor.map(process_url, urls)

if __name__ == "__main__":
    main()
