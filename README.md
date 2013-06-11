burpSaveUrlList
===============

A Burp extension written in jython that saves a url list from the Burp proxy history or Burp target site map as a text file.  This is helpful for starting "list-driven" scans in other automated web vulnerabilities scanners such as HP WebInspect.  Most automated web vulnerability scanners will accept a text file list of URLs for seeding a scan.

Four Ways to Save
==================
1.) Save a url list from the entire Proxy History <br />
2.) Save a url list from in-scope items in the Proxy History <br />
3.) Save a url list from the entire Target Site Tree <br />
4.) Save a url list from in-scope items in the Target Site Tree <br />

Requirements
==================
Burp Suite v1.5.01+ is required to access the Extender API.  In order to run python extensions using Burp Suite you will need to setup Burp with the Jython Standalone .jar.


