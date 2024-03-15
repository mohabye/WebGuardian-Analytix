import re
from urllib.parse import urlparse
from collections import defaultdict

def parse_log_line(line):
    # This is a simplified regex and might need adjustments
    pattern = re.compile(r'(?P<ip>\S+) - - \[\S+ \S+\] "(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\S+) (?P<length>\S+) "\S+" "(?P<user_agent>.+)"')
    match = pattern.match(line)
    if match:
        return match.groupdict()
    return {}

def analyze_log_file(file_path):
    ip_data = defaultdict(lambda: {'count': 0, 'urls': set(), 'statuses': set(), 'methods': set(), 'user_agents': set(), 'url_details': defaultdict(lambda: {'scheme': set(), 'netloc': set(), 'path': set(), 'params': set(), 'query': set(), 'fragment': set()})})
    
    with open(file_path, 'r') as file:
        for line in file:
            data = parse_log_line(line)
            if not data:
                continue
            
            ip = data['ip']
            url = data['url']
            parsed_url = urlparse(url)
            ip_data[ip]['count'] += 1
            ip_data[ip]['urls'].add(url)
            ip_data[ip]['statuses'].add(data['status'])
            ip_data[ip]['methods'].add(data['method'])
            ip_data[ip]['user_agents'].add(data['user_agent'])
            # Store parts of the URL
            ip_data[ip]['url_details'][url]['scheme'].add(parsed_url.scheme)
            ip_data[ip]['url_details'][url]['netloc'].add(parsed_url.netloc)
            ip_data[ip]['url_details'][url]['path'].add(parsed_url.path)
            ip_data[ip]['url_details'][url]['params'].add(parsed_url.params)
            ip_data[ip]['url_details'][url]['query'].add(parsed_url.query)
            ip_data[ip]['url_details'][url]['fragment'].add(parsed_url.fragment)

    # Sort IPs based on request count
    sorted_ips = sorted(ip_data.items(), key=lambda x: x[1]['count'], reverse=True)

    # Print or save the analysis
    for ip, info in sorted_ips:
        print(f"IP: {ip}, Count: {info['count']}, URLs Accessed: {len(info['urls'])}")
        for url in info['urls']:
            details = ip_data[ip]['url_details'][url]
            print(f"    URL: {url}, Scheme: {details['scheme']}, Netloc: {details['netloc']}, Path: {details['path']}, Params: {details['params']}, Query: {details['query']}, Fragment: {details['fragment']}")
        print(f"Statuses: {info['statuses']}, Methods: {info['methods']}, User-Agents: {info['user_agents']}")

# Prompt the user to enter the log file path
log_file_path = input("Please enter the path to your log file: ")
analyze_log_file(log_file_path)
