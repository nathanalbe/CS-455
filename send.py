import socket

timeout = 5
retries = 3

def send_data(query_data, host='8.8.8.8', port=53):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        for attempt in range(retries):
            try:
                s.sendto(query_data, (host, port))
                response, _ = s.recvfrom(4096)
                print(f"DNS response received (attempt {attempt + 1})") 
                return response   
            except socket.timeout:
                print(f"Timeout occurred, retrying... (attempt {attempt + 1})")
                continue
        print("ERROR: Timeout after 3 attempts.")
        return None