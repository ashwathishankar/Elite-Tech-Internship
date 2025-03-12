# Elite-Tech-Internship


This repository conrains 5 different tools for cyber security and digital foreniscs 


1. File integrity checker 


2. Web application vulnerability scanner 


3. Penetration testing tool


4. Advanced encryption tool

📌**Tool 1- File integrity checker** 


It monitors changes in a directory by computing SHA-256 hashes of files. It detects if files have been modified, added, or deleted.


**How does it works?**


1. Reads the file in chunks (to handle large files efficiently).


2. Computes a SHA-256 hash of the file’s contents.


3. Returns a unique hexadecimal hash (like a fingerprint).


4. If the file doesn’t exist, it prints an error.


📌**Tool 2- Web application vulnerability scanner** 

It is a web vulnerability scanner that tests for SQL Injection (SQLi) and Cross-Site Scripting (XSS) by injecting common attack payloads into web forms. 


**How it works**
1. Sends a GET request to the target URL.


2. Uses BeautifulSoup to extract all elements from the webpage.


3. Returns a list of forms found on the page.


📌**Tool 3- Penetration testing tool**
a basic penetration testing toolkit with three main functionalities:

1. Port Scanner – Scans a target for open ports.


2. SSH Brute Force – Tries to guess an SSH password from a list.


3. HTTP Status Checker – Checks if a website is online.

**🔹 How it works** For port scanner


1. Uses the socket module to create a TCP connection.


2. Tries to connect to each port provided in the list.


3. If a port responds, it is considered open.


4. Useful for: Checking which services (SSH, HTTP, etc.) are running on a target.

**🔹 How it works** For SSH Brute force


1. Uses Paramiko (Python SSH library) to attempt logging in to SSH.


2. Reads passwords from a password list file and tries them one by one.


3. If login is successful, it prints the username and password.


4. If too many attempts are made, it stops (to avoid IP bans).

**🔹 How it works** For HTTP status checker


1. Sends a GET request to a given URL.


2. If the request is successful, it prints the HTTP status code (e.g., 200 OK).
 

3. If the request fails, it prints an offline message.


📌**Tool 4- Advanced encryption tool**


The script generates a 256-bit (32-byte) AES key and stores it in a file named aes_key.key.
If the key file already exists, it loads the key instead of regenerating it.

**How does it works?**
***For encryption****


1. Read the file as plaintext.


2. Generate a random IV (Initialization Vector) (16 bytes) for security.


3. Create an AES cipher using CBC mode and the previously loaded key.


4. Pad the plaintext so its length is a multiple of 16 bytes (AES block size).


5. Encrypt the plaintext using the cipher.


6. Save the IV + encrypted data to a new file (filename.enc).


**For decryption**


1. Read the encrypted file.


2. Extract the IV (first 16 bytes) and the ciphertext (remaining bytes).


3. Create an AES cipher using the same key and CBC mode.


4. Decrypt the ciphertext.


5. Remove padding (last byte indicates padding length).


6. Save the decrypted data as the original file.

