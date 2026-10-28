# Zero-trust File Transfer Protocol (ZT-FTP)

This project presents a multi-threaded client–server file sharing application implemented using TCP sockets. Security is enforced through a hybrid cryptographic approach, where public-key cryptography is used to securely distribute a symmetric secret key that encrypts all data exchanged between the client and the server. The system adopts a zero-trust security model, requiring clients to provide a valid session key for every command execution. Client authentication is performed using username and password credentials, and role-based access control is implemented to restrict operations based on assigned privileges. Additionally, the application validates client inputs to ensure robustness against malformed or malicious requests.

##  Group member names
-Ayat Abueid ID:0229098

-Ahmad Allobani

## Prerequisites & Setup
Before running the application, ensure the following requirements are met:

**1. The SQLite JDBC Driver**

The project requires the SQLite JDBC Driver to communicate with the database.

    Download: sqlite-jdbc-3.x.x.jar. 
    
Placement: If importing this project into an IDE, ensure the .jar file in this folder is added to the Project Structure > External Libraries

*Note: I used sqlite-jdbc-3.45.1.0.jar to be specific for the project.*

**2. File Requirements**

Ensure the following files are present in the project root for the "Zero-Trust" handshake and database authentication to work:

    database.db — The SQLite database containing user credentials.

    keys/server_public.key & keys/server_private.key — Used for RSA identity verification.

Note: I think this is all hopefully I didn't forget anything.

## Features and limitations

- **1. Hybrid Cryptographic Framework**  
  Combines the security of RSA-2048 (Asymmetric) for identity verification and key exchange with the speed of AES-GCM-128 (Symmetric) for file data encryption.

- **2. Digital Signatures**  
  Prevents Man-in-the-Middle (MitM) attacks by signing the server's public key. The client verifies this "identity card" against a local trusted key before proceeding.

- **3. End-to-End Encryption**  
  All traffic including usernames, passwords, file names, and file contents is encrypted before it leaves the source.  
  But of course there's a backdoor for admin.

- **4. Hashed Passwords**
  Implements SHA-256 password hashing so that plain-text passwords never travel over the network!

- **5. Binary Support**
   Uses DataInputStream and DataOutputStream to handle raw byte arrays, allowing for any file type (Images, PDFs, Executables, etc.) beyond simple text.
  
- **6. Authentication**
 Clients authenticate before using any service. Use a simple username/password mechanism to login.

- **7. Per-Command Session Keys**
The server assumes every request is a potential attack. To mitigate this, a unique Session Key is generated upon login and must be attached to every subsequent command packet.
Which provides non-repudiation as well users cannot deny their actions on the server.

- **8. Brute-Force Protection**
The server enforces a strict 3-attempt limit for both initial logins and session key validations. Exceeding these limits results in an immediate socket termination.

- **9. Role-Based Access Control (RBAC) User Isolation**
Standard users are strictly jailed within a directory named after their unique UUID. They cannot navigate to or see other users' files.

- **10. Role-Based Access Control (RBAC) Administrative Privileges**
Users with the admin role can perform management tasks across the entire system

- **11 .Strict Path Sanitization**
The server strips directory traversal markers (e.g., ../) from all client-provided filenames, preventing Path Traversal Attacks.

- **12 .Multi-threaded Architecture**
The server utilizes a Thread-per-Client mode

- **13 .Thread-Safe Logging**
Implements a synchronized logging mechanism using a global monitor lock. This prevents "race conditions" where multiple threads might overlap their log entries, ensuring the audit trail remains readable.

- **14 .Secure Password Storage:**
The system stores only SHA-256 hashes of passwords. Even if the database file is stolen, the original passwords remain protected.

- **15 .Remote File Operations**
Users can list available files, upload new data, download existing files, and delete files from their assigned remote directory.

