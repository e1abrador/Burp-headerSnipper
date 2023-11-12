from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab
from javax.swing import JPanel, JLabel, JTextField, BoxLayout, Box, JScrollPane, JTextArea
from java.awt import Dimension
from java.awt.event import FocusListener

class CustomFocusListener(FocusListener):
    def __init__(self, custom_header_tab):
        self.custom_header_tab = custom_header_tab

    def focusGained(self, event):
        pass  # No action needed on focus gain

    def focusLost(self, event):
        self.custom_header_tab.applySnipping()  # Apply changes when focus is lost

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    headers_to_snip = ['Cookie']  # Global variable for headers to snip
    all_tabs = []  # Keep track of all tab instances

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        callbacks.setExtensionName("CustomHeaderSnipper")
        callbacks.registerMessageEditorTabFactory(self)

    def createNewInstance(self, controller, editable):
        return CustomHeaderTab(self.callbacks, controller, editable)

    @staticmethod
    def updateAllHeaderFields(new_headers):
        BurpExtender.headers_to_snip = new_headers
        for tab in BurpExtender.all_tabs:
            tab.updateHeaderInputField()

class CustomHeaderTab(IMessageEditorTab):
    def __init__(self, callbacks, controller, editable):
        self.callbacks = callbacks
        self._controller = controller
        self._editable = editable
        self._txtInput = callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        self.original_message = None
        self.setup_ui()
        BurpExtender.all_tabs.append(self)  # Add this tab to the list

    def setup_ui(self):
        self._panel = JPanel()
        self._panel.setLayout(BoxLayout(self._panel, BoxLayout.Y_AXIS))
        self._headersLabel = JLabel("Headers to be snipped.")
        self._panel.add(self._headersLabel)

        self._headerInput = JTextField()
        self._headerInput.setMaximumSize(Dimension(400, self._headerInput.getPreferredSize().height))  # Set the maximum size
        self._headerInput.addFocusListener(CustomFocusListener(self))
        self._panel.add(self._headerInput)
        self._panel.add(Box.createVerticalStrut(10))
        self._panel.add(self._txtInput.getComponent())

    def updateHeaderInputField(self):
        headers_text = ', '.join(BurpExtender.headers_to_snip)
        self._headerInput.setText(headers_text)

    def applySnipping(self):
        new_headers = self.getHeadersToSnip()
        BurpExtender.updateAllHeaderFields(new_headers)
        modified_content = self.snip_headers(self.original_message, new_headers)
        self._txtInput.setText(self.callbacks.getHelpers().bytesToString(modified_content))

    def getUiComponent(self):
        return self._panel

    def getTabCaption(self):
        return "Snipped Request"

    def isEnabled(self, content, isRequest):
        return isRequest

    def setMessage(self, content, isRequest):
        if isRequest:
            self.original_message = content
            modified_content = self.snip_headers(content, BurpExtender.headers_to_snip)
            self._txtInput.setText(self.callbacks.getHelpers().bytesToString(modified_content))
            self.updateHeaderInputField()

    def getHeadersToSnip(self):
        user_input = self._headerInput.getText().strip()
        if user_input:
            return [header.strip() for header in user_input.split(',')]
        return BurpExtender.headers_to_snip

    def snip_headers(self, content, headers_to_snip):
        request_info = self.callbacks.getHelpers().analyzeRequest(content)
        headers = request_info.getHeaders()
        modified_headers = []

        for header in headers:
            header_name = header.split(':')[0]
            if header_name in headers_to_snip:
                modified_headers.append("{}: ............SNIPPED HEADER...............".format(header_name))
            else:
                modified_headers.append(header)

        body_bytes = content[request_info.getBodyOffset():]
        modified_message = self.callbacks.getHelpers().buildHttpMessage(modified_headers, body_bytes)
        return modified_message

    def getMessage(self):
        return self._txtInput.getText()

    def isModified(self):
        return self._txtInput.isTextModified()

    # Ensure to remove the tab instance when it's no longer needed
    def finalize(self):
        BurpExtender.all_tabs.remove(self)
