from burp import IBurpExtender, IHttpListener, ITab, IMessageEditorController, IHttpRequestResponse, IHttpService
from javax.swing import JFrame, JPanel, JTable, JScrollPane, JTextArea, table, BoxLayout, JTabbedPane, JSplitPane
from java.awt import BorderLayout, Color, Dimension
from java.awt.event import MouseAdapter, KeyEvent, KeyAdapter


class MyMouseListener(MouseAdapter):
    def __init__(self, table, extender):
        self.table = table
        self.extender = extender

    def mouseClicked(self, e):
        row = self.table.getSelectedRow()
        if row != -1:
            # Perform the desired action when the user clicks on a row
            self.extender._requestViewer.setMessage(self.extender.data_requests[row], True)
            self.extender._responseViewer.setMessage(self.extender.data_responses[row], False)

class MyKeyListener(KeyAdapter):
    def __init__(self, table, extender):
        self.table = table
        self.extender = extender

    def keyPressed(self, e):
        row = self.table.getSelectedRow()
        if row != -1 and e.getKeyCode() == KeyEvent.VK_UP or e.getKeyCode() == KeyEvent.VK_DOWN:
            self.extender._requestViewer.setMessage(self.extender.data_requests[row], True)
            self.extender._responseViewer.setMessage(self.extender.data_responses[row], False)

class BurpExtender(IBurpExtender, IHttpListener, ITab, IMessageEditorController, IHttpService, IHttpRequestResponse):
    
    def __init__(self):
        self.data = []
        self.data_requests = []
        self.data_responses = []
        self.panel = None
        self.tableModel = None
        self.id = 0
        self.modified_cookie_header = []
        self.textArea = []
        self.splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self.splitpane.setPreferredSize(Dimension(800,450))
        self.myTable = JTable()
        self._requestViewer = any
        self._responseViewer = any
        self.editor_panel = JPanel(BorderLayout())

    def getTabCaption(self):
        return "Cookie Monsta"

    def getUiComponent(self):
        if not self.panel:  # Only create panel once
            panel = JPanel(BorderLayout())

            # Tabel UI
            panel_table = JPanel()
            panel_table.setLayout(BoxLayout(panel_table, BoxLayout.Y_AXIS))
            head = ['ID', 'Method', 'URL', 'XSS']
            self.tableModel = table.DefaultTableModel(self.data, head)
            
            self.myTable.setModel(self.tableModel) 
            self.myTable.setAutoCreateRowSorter(True)
            panel_table.add(self.myTable.getTableHeader())
            panel_table.add(JScrollPane(self.myTable))
            self.myTable.autoResizeMode = JTable.AUTO_RESIZE_ALL_COLUMNS
            self.myTable.columnModel.getColumn(0).preferredWidth = 10
            self.myTable.columnModel.getColumn(1).preferredWidth = 10
            self.myTable.columnModel.getColumn(2).preferredWidth = 550
            self.myTable.columnModel.getColumn(3).preferredWidth = 50

            self.myTable.addMouseListener(MyMouseListener(self.myTable, self))
            self.myTable.addKeyListener(MyKeyListener(self.myTable, self))

            # Sidebar UI - TextArea to add cookies
            panel_sidebar = JPanel()
            panel_sidebar.setPreferredSize(Dimension(350,100))
            self.textArea = JTextArea()
            self.textArea.setPreferredSize(Dimension(325,100))
            self.textArea.setLineWrap(True)
            self.textArea.setWrapStyleWord(True)
            panel_sidebar.add(self.textArea)

            # Add UI to Panel
            panel.add(panel_table)
            panel.add(panel_sidebar, BorderLayout.EAST)
            panel.add(self.splitpane, BorderLayout.SOUTH)
        return panel
    
    def updateTable(self):
        self.tableModel.setDataVector(self.data, ['ID', 'Method', 'URL' ,'XSS'])
        self.myTable.autoResizeMode = JTable.AUTO_RESIZE_ALL_COLUMNS
        self.myTable.columnModel.getColumn(0).preferredWidth = 10
        self.myTable.columnModel.getColumn(1).preferredWidth = 10
        self.myTable.columnModel.getColumn(2).preferredWidth = 750
        self.myTable.columnModel.getColumn(3).preferredWidth = 50
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.registerHttpListener(self)
        callbacks.setExtensionName("Cookie Monsta")
        callbacks.addSuiteTab(self)
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)

        # Add Message Editor to UI
        tabs = JTabbedPane()
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self.editor_panel.add(tabs)
        self.splitpane.setLeftComponent(self.editor_panel)


    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Check if message received is a request or response
        if(messageIsRequest):
            request = messageInfo.getRequest()
            request_data = self._helpers.analyzeRequest(request)
            headers = request_data.getHeaders()
            

            # Get the cookies to exclude from XSS appending
            cookies_to_exclude = self.textArea.getText()
        
            # Extract cookies from headers
            modified_headers = []
            for header in headers:
                if header.startswith("Cookie: "):
                    cookie_header = header[len("Cookie: "):]
                    cookie_parts = cookie_header.split("; ")
                    modified_cookie_parts = []
                    for part in cookie_parts:
                        if "=" in part:
                            name, value = part.split("=", 1)
                            if(name not in cookies_to_exclude):
                                modified_value = value.strip() + "xxxx1'xxxx2\"xxxx3>xxxx4<"
                            else:
                                modified_value = value.strip()
                            modified_cookie_parts.append("{}={}".format(name, modified_value))
                            
                        else:
                            modified_cookie_parts.append(part)
                    self.modified_cookie_header = "Cookie: " + "; ".join(modified_cookie_parts)
                    modified_headers.append(self.modified_cookie_header)
                else:
                    modified_headers.append(header)

            # Since we are sending a modified request, it will be intercepted and cause an infinte loop.
            # This check is used to make sure that the modified request doesn't get intercepted again
            for header in headers:
                if(header.startswith("X-Cookie-Monsta: ")):
                    return

            # Append Cookie-Monsta Header to request in order to track later
            modified_headers.append("X-Cookie-Monsta: true")


            try:
                modified_request = self._helpers.buildHttpMessage(modified_headers, request[request_data.getBodyOffset():])
                new_request = self._callbacks.makeHttpRequest(messageInfo.getHttpService(), modified_request)
                new_request_data = self._helpers.analyzeRequest(new_request)
            except Exception as err:
                print("HERE" + str(err))

                url = new_request_data.getUrl()

                # Check if the URL is within the current scope
                if not self._callbacks.isInScope(url):
                    return

                # Get the response to the new request
                response = new_request.getResponse()
                response_data = self._helpers.analyzeResponse(response)

                # Find response body and check if "XSS" is reflected
                response_body = response[response_data.getBodyOffset():]
                if response_data.getBodyOffset() != -1:
                    reflected = []
                    if "xxxx1'" in self._helpers.bytesToString(response_body):
                        reflected.append("'")
                    elif "xxxx2\"" in self._helpers.bytesToString(response_body):
                        reflected.append("\"")
                    elif "xxxx3>" in self._helpers.bytesToString(response_body):
                        reflected.append(">")
                    elif "xxxx4<" in self._helpers.bytesToString(response_body):
                        reflected.append("<")
                    
                    # self.data.append([self.id, new_request_data.getMethod(), new_request_data.getUrl(), reflected]) # DEBUG
                    # self.id = self.id + 1 # DEBUG
                    # self.data_requests.append(modified_request) # DEBUG
                    # self.data_responses.append(response) # DEBUG
                    # print(self.data)
                    if(reflected):
                        self.data.append([self.id, new_request_data.getMethod(), new_request_data.getUrl(), reflected]) 
                        self.id = self.id + 1 
                        self.data_requests.append(modified_request) 
                        self.data_responses.append(response) 

                        # Update the JTable after updating the data
                        self.updateTable()
                    
                else:
                    print("No response body")
            
            
