# Harden your Server Configuration to Prevent Unwanted Cyber Attacks

# 1. Blind SQL Injection
SQL injection is a vulnerability that allows an attacker to alter back-end SQL statements by manipulating the user input. An SQL injection occurs when web applications accept user
input that is directly placed into a SQL statement and doesn't properly filter out dangerous characters.Blind SQL injection is a type of SQL Injection attack, an attacker is forced to steal data by asking the database a series of true or false questions. This makes exploiting the SQL Injection vulnerability more difficult, but not impossible.

Impact: High

Recommendation and Mitigation Strategies:
  - White List Input Validation
  - Don't use dynamic SQL when it can be avoided
  - Limit database privileges by context
  - Avoid disclosing database error information

# 2. Clickjacking

The application response headers contain missing X-Frame-Field options. Which may allow attacker to inject some other page using Iframe code.

Impact: Intermediate (If an attacker carefully crafted combination of stylesheets, iframes, and text boxes, a user can be led to believe they are typing in the password to their email or bank account, but are instead typing into an invisible frame controlled by the attacker.)

Recommendation and Mitigation Strategies:

Please enable X-Frame-Options and set it to “DENY”, “SAME ORIGIN” or “ALLOW-FROM uri”.
  - X-Frame-Options: DENY « won’t allow the website to be framed by anyone.
  - X-Frame-Options: SAMEORIGIN « No one can frame except for sites from same origin.
  - X-Frame-Options: ALLOW-FROM uri « which permits the specified 'uri' to frame this page.(e.g., ALLOW-FROM http://www.example.com).

```sh
   # Add the follwing line in httpd.conf
   Header always append X-Frame-Options SAMEORIGIN
```
# 3. Weak Ciphers Enabled
If weak ciphers are enabled during secure communication (SSL). Should allow only strong ciphers on web server to protect secure communication with visitors.

Impact: High (Attackers might decrypt SSL traffic between server and visitors.)

Recommendation and Mitigation Strategies:
```sh
   # For Apache, modify the SSLCipherSuite directive in the httpd.conf.
   SSLCipherSuite
   ALL:!aNULL:!ADH:!eNULL:!LOW:!EXP:RC4+RSA:+HIGH:+MEDIUM
```

List of Supported weak cipher :
  - TLS_RSA_WITH_RC4_128_SHA (0x0005)
  - TLS_RSA_WITH_RC4_128_MD5 (0x0004)
  - TLS_ECDHE_RSA_WITH_RC4_128_SHA (0xC011)

# 4. Disable nginx/apache server_tokens

The application page header is displaying sensitive information such as version disclosure and other details.

Impact: Medium

Recommendation and Mitigation Strategies:

Use the Server Tokens and Server Signature directives in web.config to control what is being displayed in the page response headers.
Remove or Disable the Server Name/Version setting in response headers.

```sh
   # Add the follwing line in httpd.conf
    ServerTokens Prod
    ServerSignature Off
  # For nginx modify ServerTokens in /etc/nginx.conf
    server_tokens off
```

# 5. Directory Listing Enabled
The web server is configured to display the list of all files contained in this directory. This is not recommended because the directory may contain files that are not normally exposed through links on the web site.

Impact: Medium (A user can view a list of all files from this directory possibly exposing sensitive information.)

Recommendation and Mitigation Strategies:
Disable the directory listing.
```sh
   # Modify the follwing line in httpd.conf
     Options Indexes FollowSymLinks  => Options FollowSymLinks
   # Directory listing is disabled by default on the nginx.
```
# 6.Control Resources and Limits 
To prevent potential DoS attacks on nginx, you can set buffer size limitations for all clients. You can do this in the nginx configuration file using the following directives:
   - Limiting number of connections - ou can limit the number of connections that can be opened by a single client IP address, 
```sh
       limit_conn two 10;
```
   This example creates a memory zone called two to store requests for the specified key, in this case the client IP address, $binary_remote_addr. Then the limit_conn directive sets #a maximum of 10 connections from each client IP address.
   
  - Timeout parameters - Slow connections can represent an attempt to keep connections open for a long time. As a result, the server can’t accept new connections.
```sh
       client_body_timeout 5s;
       client_header_timeout 5s;
```
  - Limit requests size - Similarly, large buffer values or large HTTP requests size make DDoS attacks easier. So, we limit the following buffer values in the Nginx configuration file to mitigate DDoS attacks.
```sh
      client_body_buffer_size 200K;
      client_header_buffer_size 2k;
      client_max_body_size 200k;
      large_client_header_buffers 3 1k;
```
   - WhiteList/BlackList IPs - you can identify the client IP addresses being used for an attack, you can blacklist them with the deny directive.If access to your website or application is allowed only from one or more specific sets or ranges of client IP addresses.  you can use the allow and deny directives together to allow only those addresses to access the site or application.
```sh
       allow 123.123.123.3;
       deny all;
```

# 7. Insecure Transportation Security Protocol Supported (SSLv3)
The web site is supported by insecure transportation security protocol (SSLv3). SSLv3 has several flaws. An attacker can cause connection failures and they can trigger the use of SSL 3.0 to exploit vulnerabilities like POODLE.

Impact: Medium (Attackers can perform man-in-the-middle attacks and observe the encryption traffic between your website and its visitors.)

Recommendation and Mitigation Strategies:
Configure your web server to disallow using weak ciphers.
For Apache, adjust the SSLProtocol directive provided by the mod_ssl module. This directive can be set either at the server level or in a virtual host configuration.
SSLProtocol +TLSv1.1 +TLSv1.2
```sh
       grep -r ssl_protocol /etc/nginx
       #The command will out put the available Server Blocks.
       #Open the Server Block for which you are disabling the SSL v3 protocol.
       ssl_protocols TLSv1.2 TLSv1.1 TLSv1;
```
# 8. Out of date Version (Framework & Compiler)
It’s having many security flaws which allows an attacker to perform Remote Code Execution and Denial of Service Attacks.

Impact: Low (an old version of the software, it may be vulnerable to attacks.)

Recommendation and Mitigation Strategies:

Upgrade with the latest stable version.

# 9. Disable any unwanted HTTP method
We suggest that you disable any HTTP methods, which are not going to be utilized and which are not required to be implemented on the web server. If you add the following condition in the location block of the nginx virtual host configuration file, the server will only allow GET, HEAD, and POST methods and will filter out methods such as DELETE and TRACE.

Imcpact: Low (The TRACE method may expose sensitive information that may help a malicious user to prepare more advanced attacks.)

Recommendation and Mitigation Strategies:
It's recommended to disable OPTIONS, TRACE Methods on the web server.
Microsoft provides the following tools to apply certain criteria and turning off unnecessary features:

```sh
       location / {
       limit_except GET HEAD POST { deny all; }
       }
```

# 10. Install ModSecurity for Your nginx Web Server

ModSecurity is an open-source module that works as a web application firewall. Its functionalities include filtering, server identity masking, and null-byte attack prevention. The module also lets you perform real-time traffic monitoring. We recommend that you follow the ModSecurity manual to install the mod_security module in order to strengthen your security options.
```sh
        location / {
        ModSecurityEnabled on; 
        ModSecurityConfig modsecurity.conf;
        }      
```
# 11. Cookie Marked as Secure flag
If the secure flag is set on a cookie, then browsers will not submit the cookie in any requests that use an unencrypted HTTP connection, thereby preventing the cookie from being trivially intercepted by an attacker monitoring network traffic. If the secure flag is not set, then the cookie will be transmitted in clear-text if the user visits any HTTP URLs within the cookie's scope.

Impact: Low (An attacker may be able to induce this event by feeding a user suitable links, either directly or via another web site.)

Recommendation and Mitigation Strategies:
Set the Secure flag and HttpOnly flag for this cookie.
```sh
        #just put this in your .htaccess
        php_value session.cookie_httponly 1
        php_value session.cookie_secure 1
```

# 12. Same-Site Cookie Attribute set
Same-site cookies allow servers to mitigate the risk of CSRF and information leakage attacks by asserting that a particular cookie should only be sent with requests initiated
from the same registrable domain.

Impact: Low (Cookies are typically sent to third parties in cross origin requests. This can be abused to do CSRF attacks.)

Recommendation and Mitigation Strategies:
The server can set a same-site cookie by adding the SameSite=... attribute to the Set-Cookie header:
Set-Cookie: key=value; SameSite=strict

# 13. HTTP Strict Transport Security (HSTS) Policy Not Enabled
HTTP Strict Transport Security (HSTS) is a web security policy mechanism whereby a web server declares that complying user agents (such as a web browser) are to
interact with it using only secure HTTP (HTTPS) connections. The HSTS Policy is communicated by the server to the user agent via a HTTP response header field named
"Strict-Transport-Security". HSTS Policy specifies a period of time during which the user agent shall access the server in only secure fashion. When a web application issues HSTS Policy to user agents, conformant user agents behave as follows:

- Automatically turn any insecure links referencing the web application into secure
links. (For instance, http://example.com/some/page/ will be modified to https://example.com/some/page/ before accessing the server.)

If the security of the connection cannot be ensured (e.g. the server's TLS certificate is self-
signed), show an error message and do not allow the user to access the web application.

Impact: intermediate

Recommendation and Mitigation Strategies:

Configure your webserver to redirect HTTP requests to HTTPS.
For Apache, you should have modification in the httpd.conf.
```sh
# load module
LoadModule headers_module modules/mod_headers.so
# redirect all HTTP to HTTPS (optional)
<VirtualHost *:80>
ServerAlias *
RewriteEngine On
RewriteRule ^(.*)$ https://%{HTTP_HOST}$1 [redirect=301]
</VirtualHost>
# HTTPS-Host-Configuration
<VirtualHost *:443>
# Use HTTP Strict Transport Security to force client to use secure connections only
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
# Further Configuration goes here
[...]
</virtualHost>
```
# 14. X-Content-Type-Options Header
This header only has one valid value, nosniff. It prevents Google Chrome and Internet Explorer from trying to mime-sniff the content-type of a response away from the one being
declared by the server. It reduces exposure to drive-by downloads and the risks of user uploaded content that, with clever naming, could be treated as a different content-type, like
an executable.

Impact: Low

Recommendation and Mitigation Strategies:

Prevents possible phishing or XSS attacks
```sh
     set X-Content-Type-Options "nosniff"
```

# 15. X-XSS Protection Header
This header is used to configure the built in reflective XSS protection found in Internet Explorer, Chrome and Safari (Webkit). Valid settings for the header are 0, which disables
the protection, 1 which enables the protection and 1; mode=block which tells the browser to block the response if it detects an attack rather than sanitizing the script.

Impact: Low

Recommendation and Mitigation Strategies:
Mitigates Cross-Site Scripting (XSS) attacks

```sh
     set X-Xss-Protection "1; mode=block"
```





