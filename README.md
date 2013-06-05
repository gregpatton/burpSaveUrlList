burpSaveUrlList
===============

A Burp Extension written in jython that saves a URL List from the Burp Proxy History or Burp Target Site Map as a text file.  This is helpful for starting "List-Driven" scans in other automated web vulnerabilities scanners such as HP WebInspect.  Most automated web vulnerability scanner will accept a txt file list of URLs for seeding a scan.

Requirements
==================
Burp Suite v1.5.01+ is required to access the Extender API.  In order to run python extensions using Burp Suite you will need to setup Burp with the Jython Standalone .jar.


