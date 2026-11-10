# -*- coding: utf-8 -*-
"""路径特征库。

单独放一个模块是因为它同时被报表（判断敏感文件是否被读走）和
策略引擎（判断是否在探测敏感文件）使用，放在 report 里会造成循环依赖。
"""

import re

# 命中即视为"敏感文件"，需要结合状态码和响应体大小进一步确认是否真的泄漏
SENSITIVE = re.compile(
    r"(\.env|\.git|\.sql|\.bak|\.zip|\.tar|\.pem|\.key|\.p12|credentials|"
    r"config\.(json|yml|yaml|toml)|wp-(admin|login|content)|phpmyadmin|"
    r"actuator|swagger|\.aws/|service-account|id_rsa|passwd|/etc/)",
    re.I,
)

# 蜜罐路径：一个纯静态站上永远不该有人访问的地址。
# 和 SENSITIVE 的区别是"命中一次就足够判定"——正常用户不会手抖打开 /xmlrpc.php，
# 会访问这些地址的只有扫描器、漏洞利用脚本和被入侵后回连的僵尸网络。
HONEYPOT = re.compile(
    r"("
    r"/wp-(login|admin|includes|content|config|signup|json)|/xmlrpc\.php|"
    r"/wlwmanifest\.xml|/\.(git|svn|hg|env|aws|ssh|htaccess|DS_Store)|"
    r"/(phpmyadmin|pma|myadmin|adminer|dbadmin|sql\.php)|"
    r"/actuator|/solr/|/jmx-console|/web-console|/console|/manager/html|"
    r"/HNAP1|/boaform/|/GponForm/|/setup\.cgi|/cgi-bin/|"
    r"/vendor/phpunit|/phpunit|/telescope|/_ignition|/server-(status|info)|"
    r"/owa/|/autodiscover|/ecp/|/remote/login|\+CSCOE\+|"
    r"/config\.php\.(bak|old|swp)|/dump\.sql|/backup\.(sql|zip|tar|gz)"
    r")",
    re.I,
)

# 扫描器的 User-Agent 指纹。只放工具名，不放 curl / python-requests 这种
# 正常脚本也在用的标记——误封脚本比漏封一个扫描器麻烦得多。
BAD_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|zgrab|nuclei|gobuster|dirsearch|dirb|wfuzz|"
    r"ffuf|feroxbuster|wpscan|joomscan|droopescan|xray|acunetix|netsparker|"
    r"nessus|openvas|whatweb|w3af|skipfish|arachni|jaeles|havij|commix|"
    r"censys|shodan|internet-measurement|netsystemsresearch|paloalto|"
    r"zmeu|morfeus|fuzzdb)",
    re.I,
)
