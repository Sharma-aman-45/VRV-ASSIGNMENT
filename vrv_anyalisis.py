import re
import csv
from collections import defaultdict

def parse_log_file(file_path):
    """Parses the log file and returns the extracted IPs, endpoints, and failed login entries."""
    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    endpoint_pattern = r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS) (.*?) HTTP'
    failed_login_pattern = r'(401|Invalid credentials)'

    ip_count = defaultdict(int)
    endpoint_count = defaultdict(int)
    failed_logins = defaultdict(int)

    with open(file_path, 'r') as log_file:
        for line in log_file:
            # Extract IP addresses
            ip_match = re.search(ip_pattern, line)
            if ip_match:
                ip = ip_match.group()
                ip_count[ip] += 1
            
            # Extract endpoints
            endpoint_match = re.search(endpoint_pattern, line)
            if endpoint_match:
                endpoint = endpoint_match.group(2)
                endpoint_count[endpoint] += 1
            
            # Detect failed login attempts
            if re.search(failed_login_pattern, line):
                if ip_match:  # IP associated with the failed attempt
                    failed_logins[ip] += 1

    return ip_count, endpoint_count, failed_logins

def save_to_csv(file_name, ip_data, endpoint_data, suspicious_data):
    """Saves the analysis results to a CSV file."""
    with open(file_name, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        
        # Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_data.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])
        
        # Most accessed endpoint
        writer.writerow([])
        writer.writerow(["Endpoint", "Access Count"])
        for endpoint, count in sorted(endpoint_data.items(), key=lambda x: x[1], reverse=True)[:1]:
            writer.writerow([endpoint, count])
        
        # Suspicious activity
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_data.items():
            writer.writerow([ip, count])

def main():
    log_file_path = input("Enter the log file path: ")
    threshold = int(input("Enter the threshold for failed login attempts (default is 10): ") or 10)

    # Analyze the log file
    ip_count, endpoint_count, failed_logins = parse_log_file(log_file_path)

    # Display results
    print("\nRequests per IP Address:")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    for ip, count in sorted(ip_count.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count:<15}")

    print("\nMost Frequently Accessed Endpoint:")
    most_accessed = max(endpoint_count.items(), key=lambda x: x[1])
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts':<15}")
    for ip, count in failed_logins.items():
        if count > threshold:
            print(f"{ip:<20} {count:<15}")

    # Save results to a CSV file
    save_to_csv("log_analysis_results.csv", ip_count, endpoint_count, {ip: count for ip, count in failed_logins.items() if count > threshold})
    print("\nResults saved to log_analysis_results.csv")

if __name__ == "__main__":
    main()
