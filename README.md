# Lazy Admin - TryHackMe WriteUp
# By 0xRar



## Scanning
```
nmap -T4 -p- -A -sC -Pn 10.10.207.204
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-22 19:12 EST
Nmap scan report for 10.10.207.204
Host is up (0.15s latency).
Not shown: 65532 closed ports
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
|   256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
|_  256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (ED25519)
80/tcp    open     http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- We see that we have port 80 open lets check that out first:
`http://MACHINE_IP:80` we can see the Apache2 Ubuntu Default Page.


lets check what directories do we have:
```
/

gobuster dir -u 10.10.207.204 -w /usr/share/wordlists/dirb/common.txt

/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/content (Status: 301)
/index.html (Status: 200)
/server-status (Status: 403)



/content

gobuster dir -u 10.10.207.204/content -w /usr/share/wordlists/dirb/common.txt

/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/_themes (Status: 301)
/as (Status: 301)
/attachment (Status: 301)
/images (Status: 301)
/inc (Status: 301)
/index.php (Status: 200)
/js (Status: 301)

```

> By taking a look at the source code of the `/content`
> we can see that we have a js linked `http://10.10.207.204/content/js/SweetRice.js`
> by checking the js file we see that the `cms: SweetRice version is 0.5.4`

- Now that we have the cms name and version we can search for exploits
```
searchsploit SweetRice

this gave us 8 exploits but the one we need is:
SweetRice < 0.6.4 - 'FCKeditor' Arbitrary File Upload
(https://www.exploit-db.com/exploits/14184)
```
