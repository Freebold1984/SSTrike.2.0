from core.utils import randomUpper, genGen, extractScripts
from core.config import xsschecker
from core.payload_groups import (
    html_context_payloads,
    attribute_context_payloads,
    script_context_payloads,
    template_context_payloads,
    prototype_pollution
)
from core.encoders_enhanced import get_encoded_payloads, encode_payload_for_context, get_waf_bypass_encodings

def fuzzer_enhanced(url, params, headers, GET, delay, timeout, WAF, encoding, positions, skip):
    """Enhanced fuzzer that includes template injection, prototype pollution checks, and advanced encoding"""
    
    def get_context_payloads(context, details=None):
        """Get payloads based on the context"""
        if context == 'html':
            payloads = html_context_payloads
        elif context == 'attribute':
            payloads = attribute_context_payloads
        elif context == 'script':
            payloads = script_context_payloads
        elif context == 'template':
            payloads = template_context_payloads
        elif context == 'prototype':
            payloads = prototype_pollution
        else:
            payloads = []

        # Apply appropriate encoding for each payload based on context
        encoded_payloads = []
        for payload in payloads:
            # Get different encoding variations
            encoded_versions = encode_payload_for_context(payload, context)
            if isinstance(encoded_versions, list):
                encoded_payloads.extend(encoded_versions)
            else:
                encoded_payloads.append(encoded_versions)

        # If WAF is detected, add WAF bypass encodings
        if WAF:
            for payload in payloads:
                encoded_payloads.extend(get_waf_bypass_encodings(payload))

        return encoded_payloads

    def adapt_payload(payload, context, details=None):
        """Adapt payload based on context and details"""
        if context == 'attribute':
            quote = details.get('quote', '')
            return quote + payload + quote
        elif context == 'script':
            # For script context, try to break out of existing strings/comments
            if details and 'inString' in details:
                quote_type = details['quote']
                return quote_type + ';' + payload + ';' + quote_type
        return payload

    # Return enhanced fuzzing results with encoded variations
    results = {
        'template_payloads': get_context_payloads('template'),
        'pollution_payloads': get_context_payloads('prototype'),
        'context_payloads': {
            'html': get_context_payloads('html'),
            'attribute': get_context_payloads('attribute'),
            'script': get_context_payloads('script')
        }
    }

    # Add encoding information to results
    results['encoding_info'] = {
        'waf_detected': bool(WAF),
        'encodings_used': [
            'HTML', 'URL', 'Double URL',
            'Base64', 'Unicode', 'Mixed'
        ]
    }

    return results
