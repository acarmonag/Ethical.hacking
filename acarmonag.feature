## Version 1.4.1
## language: en

Feature: 
  TOE: 
    COLDDBOX: EASY
  Category: 
    WordPress
  Location: 
    https://192.168.56.103/
  CWE: 
    CWE-377: Insecure Temporary File
    https://cwe.mitre.org/data/definitions/377.html
    CWE-320: Key Management Errors  
    https://cwe.mitre.org/data/definitions/320.html
    CWE-1214: Data Integrity Issues
    https://cwe.mitre.org/data/definitions/1214.html
    CWE-275: Permission Issues
    https://cwe.mitre.org/data/definitions/275.html
    CWE-434: Unrestricted Upload of File with Dangerous Type
    https://cwe.mitre.org/data/definitions/434.html
  Rule: 
    REQ.172: Encrypt connection strings
    https://docs.fluidattacks.com/criteria/requirements/172
  Goal: 
    Get user and root flags
  Recommendation: 
    Update WordPress to the latest version
    Encrypt database connection strings
    Protect configuration files
    Use of secure passwords

  Background: 
  Hacker's software:
    | <Software name> | <Version>   |
    | Kali            | 2022.3      |
    | Firefox         | 91.11.0esr  |
    | Netdiscover     | 0.9         |
    | Nmap            | 7.92        |
    | Nessus          | 10.3.0      |
    | Wpscan          | 3.8.22      |

  TOE information:
    Given a .ova file executed in VirtualBox
    And using Netdiscover to get the IP address [evidence](1.png)
    And using Nmap to get the open ports [evidence](2.1.png)(2.2.png)(2.3.png)
    And found the IP address 192.168.56.103 has a WordPress site [evidence](3.png)
    And found the port 80 whit tcp (Apache httpd 2.4.18)
    And found the port 4512 whit ssh (OpenSSH 7.2p2 Ubuntu 4ubuntu2.10)
    And usign Nessus to scan the TOE finding 17 vulnerabilities [evidence](4.png)
    And using Wpscan to scan the TOE finding Usernames and Passwords [evidence](5.png)

  Scenario: Normal use case
    Given a site http://192.168.56.103/
    When i access the site
    Then i see the home page of the site
    And see the coments of the site
    Then can coment adding a name and a email and a coment
    And can see the login page

  Scenario: Dynamic detection
    Given the Ip address (using Netdiscover)
    And the rockyou.txt file
    Then use Wpscan to enumerate the Usernames
    $ wpscan --url 192.168.56.103 -e u 
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://192.168.56.103/ [192.168.56.103]
[+] Started: Sat Oct  8 14:57:33 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://192.168.56.103/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://192.168.56.103/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://192.168.56.103/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.1.31 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://192.168.56.103/?feed=rss2, <generator>https://wordpress.org/?v=4.1.31</generator>
 |  - http://192.168.56.103/?feed=comments-rss2, <generator>https://wordpress.org/?v=4.1.31</generator>

[+] WordPress theme in use: twentyfifteen
 | Location: http://192.168.56.103/wp-content/themes/twentyfifteen/
 | Last Updated: 2022-05-24T00:00:00.000Z
 | Readme: http://192.168.56.103/wp-content/themes/twentyfifteen/readme.txt
 | [!] The version is out of date, the latest version is 3.2
 | Style URL: http://192.168.56.103/wp-content/themes/twentyfifteen/style.css?ver=4.1.31
 | Style Name: Twenty Fifteen
 | Style URI: https://wordpress.org/themes/twentyfifteen
 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen's simple, st...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://192.168.56.103/wp-content/themes/twentyfifteen/style.css?ver=4.1.31, Match: 'Version: 1.0'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <========> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] the cold in person
 | Found By: Rss Generator (Passive Detection)

[+] c0ldd
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] hugo
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] philip
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sat Oct  8 14:57:37 2022
[+] Requests Done: 59
[+] Cached Requests: 6
[+] Data Sent: 14.57 KB
[+] Data Received: 264.837 KB
[+] Memory used: 202.262 MB
[+] Elapsed time: 00:00:04
|
    When i get the username
    Then i use rockyou.txt whit wp scan to enumerate the passwords
    $ wpscan --url 192.168.56.103 -e u 
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://192.168.56.103/ [192.168.56.103]
[+] Started: Sat Oct  8 14:57:33 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://192.168.56.103/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://192.168.56.103/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://192.168.56.103/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.1.31 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://192.168.56.103/?feed=rss2, <generator>https://wordpress.org/?v=4.1.31</generator>
 |  - http://192.168.56.103/?feed=comments-rss2, <generator>https://wordpress.org/?v=4.1.31</generator>

[+] WordPress theme in use: twentyfifteen
 | Location: http://192.168.56.103/wp-content/themes/twentyfifteen/
 | Last Updated: 2022-05-24T00:00:00.000Z
 | Readme: http://192.168.56.103/wp-content/themes/twentyfifteen/readme.txt
 | [!] The version is out of date, the latest version is 3.2
 | Style URL: http://192.168.56.103/wp-content/themes/twentyfifteen/style.css?ver=4.1.31
 | Style Name: Twenty Fifteen
 | Style URI: https://wordpress.org/themes/twentyfifteen
 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen's simple, st...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://192.168.56.103/wp-content/themes/twentyfifteen/style.css?ver=4.1.31, Match: 'Version: 1.0'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <========> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] the cold in person
 | Found By: Rss Generator (Passive Detection)

[+] c0ldd
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] hugo
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] philip
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sat Oct  8 14:57:37 2022
[+] Requests Done: 59
[+] Cached Requests: 6
[+] Data Sent: 14.57 KB
[+] Data Received: 264.837 KB
[+] Memory used: 202.262 MB
[+] Elapsed time: 00:00:04|

    And i get the password for c0ldd user that was '9876543210'
    Then i use the credentials to login to the wordpress site [evidence](5.png)
    And move to plugin section
    And create a plugin in php to get a revshell [evidence](6.png)
    And i install the plugin and activate it [evidence](7.png)


  Scenario: Exploitation
    Given the revshell plugin
    When i use netcat to listen to port 2222
    Then i get a revshell in the user www-data[evidence](8.png)
    And i move to /var/www/html directory and cat the config file where i find the database credentials [evidence](9.png)
    And i use the command "export TERM=xterm" and "python -c 'import pty; pty.spawn("/bin/bash")'" to get a pseudo-terminal [evidence](10.png)
    And i use the credentials of the database to login to user c0ldd [evidence](10.png)
    And i move to /home/c0ldd directory 
    And i cat the user.txt file finding it is encrypted so i use "base64 -d" to get user flag  [evidence](11.png)
    Then i use the command "sudo -l" to find that i can run "/usr/bin/vim","/bin/chmod","/usr/bin/ftp" as root without password [evidence](12.png)
    And i find in GTFObins that i can use vim or ftp to get a root shell
    And i get the root flag [evidence](13.png)

  Scenario: Remediation 

    Given the file upload vulnerability
    And the Insecure password
    And the insecure config file
    Then i recomend change the password of the user c0ldd to a strong password
    And check the config file and change the database credentials
    And check the wordpress version and update it to the latest version
    Then I can confirm that the vulnerability was successfully patched

  Scenario: Scoring #M
  """
  Scoring allows the hacker to provide
  a standardized metric that reflects
  how dangerous the vulnerability is
  from three different perspectives.
  """
  Severity scoring according to CVSSv3 standard
  Base: Attributes that are constants over time and organizations
    10/10 (Critical) - AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:F/RL:W/RC:R
  Temporal: Attributes that measure the exploit's popularity and fixability
    9.3/10 (Critical) - E:F/RL:O/RC:C/
  Environmental: Unique and relevant attributes to a specific user environment
    9.3/10 (Critical) - CR:H/IR:H/AR:L

  Scenario: Correlations

    No correlations have been found to this date {2022-10-9}


  """
  Folder Naming Convention:
  In the folder structure challenges/vbd/toe/vulnerability/feature
  Hackers will often
  have to create vulnerability folders for discovered vulnerabilities in a TOE.
  Vulnerability folders will contain:
    - Only one feature file for the specific vulnerability
    - A LINK.lst file with a link to the site containing the vulnerability
    - (Optional) Evidence folder if necessary

  The following standard has been defined for vulneraility folders:
  {CWE-codenumber}-{location}-{difficulty} where:
    - {CWE-codenumber} is the codenumber of the vulnerability according to the
      Common Weakness Ennumeration (link:https://cwe.mitre.org/data/index.html)
    - {location} has to be a pointer to the vulnerability's location.
    - (optional) {difficulty} is the difficulty in which the vulnerability was
      found. All TOEs might not have a difficulty setting, that is why this is
      optional
  Some examples are (they do not necessarily exist in the repo but illustrate
  the point):
    - challenges/vbd/bwapp/352-xss-stored-2-medium/
    - challenges/vbd/dvwa/006-weak-session-ids-low/
    - challenges/vbd/webgoat/352-stored-xss/ #webgoat does not have difficulty
  """

  """
  Evidences:
  Presenting evidence of some kind of graphical output,
  like websites,
  might be difficult when using plain feature files.
  Think, for example,
  of a hacked blog via XSS that ended up with different font styles and such.
  Evidences are a way to include PNG pictures associated with a feature file
  so the hacker can graphically show anything he might consider relevant

  How they work?
  - Any feature file {name}.feature can have a {name} evidences folder in the
  same directory.
  - Evidence folders only accept PNG images
  - Evidences are referenced in two different ways:
    - Creating an <evidence> tag in a table inside a Scenario Outline like shown
      on the Extraction Scenario example
      (useful for referencing multiple evidences).
    - By using the following syntax: [evidence](image.png) like shown on the
      Normal use case Scenario example.
      (useful for referencing one or two evidences at most.)
  """