#!/usr/bin/env python

from burp import IBurpExtender
from burp import IHttpRequestResponse
from burp import IHttpService
from burp import ITab
from java.io import PrintWriter
from java.lang import RuntimeException
from javax.swing import JSplitPane
from javax.swing import JPanel
from javax.swing import JLabel
from javax.swing import JButton
from javax.swing import JFileChooser
from java.awt import Button
from java.awt import GridLayout

class BurpExtender(IBurpExtender, IHttpRequestResponse, IHttpService, ITab):

  # Implement IBurpExtenderder
  def registerExtenderCallbacks(self, callbacks):
    self.callbacks = callbacks
    self.helpers = callbacks.getHelpers()

    self.stdout = PrintWriter(callbacks.getStdout(), True)
    self.stderr = PrintWriter(callbacks.getStderr(), True)

    callbacks.setExtensionName('Save URL List')
    self.panel = JPanel()
    self.myLabel = JLabel('Create a URL List Text File', JLabel.CENTER)
    self.buttonFile = Button('Select File', actionPerformed=self.selectFile)
    self.buttonSaveProxy = Button('Save Proxy History as URL List', actionPerformed=self.saveProxy)
    self.buttonSaveSiteTree = Button('Save Target SiteTree as URL List', actionPerformed=self.saveSiteTree)
    self.panel.add(self.myLabel)
    self.panel.add(self.buttonFile)
    self.panel.add(self.buttonSaveProxy)
    self.panel.add(self.buttonSaveSiteTree)
    callbacks.customizeUiComponent(self.panel)
    callbacks.addSuiteTab(self)

  # Set title for our tab
  def getTabCaption(self):
    return 'URL List'

  # Idk what this does, but it's required
  def getUiComponent(self):
    return self.panel

  def selectFile(self, event):
    chooser = JFileChooser()
    retVal = chooser.showSaveDialog(None)
    self.saveFile = chooser.selectedFile.path

  def saveProxy(self, event):
    self.stdout.println('Writing Proxy History URL List to File: ' + self.saveFile)
    writer = open(self.saveFile, 'w')

    proxyHistory = self.callbacks.getProxyHistory()

    if proxyHistory:
      for item in proxyHistory:
        try:
          request = item.getRequest()
          if request:
            service = item.getHttpService()
            myURL = self.helpers.analyzeRequest(service, request).getUrl().toString()
            writer.write(myURL + '\n')
          else:
            self.stderr.println('Empty Request Object')

        except Exception, e:
          self.stderr.println('Error Writing URL.')
          continue

    else:
      self.stderr.println('The Proxy History is Empty')

    self.stdout.println('The Proxy History URL List List is Complete')
    writer.close()

  def saveSiteTree(self, event):
    self.stdout.println('Writing Site Tree URL List to File: ' + self.saveFile)
    writer = open(self.saveFile, 'w')
    siteMap = self.callbacks.getSiteMap('')
    lastURL = ''

    if siteMap:
      for item in siteMap:
        try:
          request = item.getRequest()
          if request:
            service = item.getHttpService()
            myURL = self.helpers.analyzeRequest(service, request).getUrl().toString()
            if myURL != lastURL:
              writer.write(myURL + '\n')
              lastURL = myURL
            else:
              self.stdout.println('Skip Duplicate: ' + myURL)
          else:
            self.stderr.println('Empty Request Object')

        except Exception, e:
          self.stderr.println('Error Writing URL.')
          continue

    else:
      self.stderr.println('The Target Site Tree is Empty')

    self.stdout.println('The Site Tree URL List File is Complete')
    writer.close()
