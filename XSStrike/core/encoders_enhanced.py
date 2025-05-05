import html
import base64
import urllib.parse

class PayloadEncoder:
    @staticmethod
    def html_encode(payload):
        """HTML encode the payload"""
        return html.escape(payload)
    
    @staticmethod
    def url_encode(payload, double=False):
        """URL encode the payload, optionally double encode"""
        encoded = urllib.parse.quote(payload)
        if double:
            encoded = urllib.parse.quote(encoded)
        return encoded
    
    @staticmethod
    def base64_encode(payload):
        """Base64 encode the payload"""
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def hex_encode(payload):
        """Convert payload to hex representation"""
        return ''.join([hex(ord(c))[2:] for c in payload])
    
    @staticmethod
    def unicode_encode(payload):
        """Convert payload to unicode escapes"""
        return ''.join(['\\u00' + hex(ord(c))[2:].zfill(2) for c in payload])
    
    @staticmethod
    def js_escape(payload):
        """Escape payload for JavaScript contexts"""
        return payload.replace('\\', '\\\\').replace('\'', '\\\'').replace('"', '\\"')

def get_encoded_payloads(payload):
    """Generate different encodings of a payload"""
    encoder = PayloadEncoder()
    encoded_versions = {
        'original': payload,
        'html': encoder.html_encode(payload),
        'url': encoder.url_encode(payload),
        'url_double': encoder.url_encode(payload, double=True),
        'base64': encoder.base64_encode(payload),
        'hex': encoder.hex_encode(payload),
        'unicode': encoder.unicode_encode(payload),
        'js_escaped': encoder.js_escape(payload)
    }
    
    # Create mixed encodings for evasion
    mixed_encodings = {
        'html_url': encoder.url_encode(encoder.html_encode(payload)),
        'url_html': encoder.html_encode(encoder.url_encode(payload)),
        'base64_url': encoder.url_encode(encoder.base64_encode(payload))
    }
    
    encoded_versions.update(mixed_encodings)
    return encoded_versions

def encode_payload_for_context(payload, context):
    """Encode payload appropriately for different contexts"""
    if context == 'html':
        return PayloadEncoder.html_encode(payload)
    elif context == 'js':
        return PayloadEncoder.js_escape(payload)
    elif context == 'url':
        return PayloadEncoder.url_encode(payload)
    elif context == 'template':
        # For template contexts, try different encoding combinations
        encodings = get_encoded_payloads(payload)
        return list(encodings.values())
    elif context == 'attribute':
        # For attribute contexts, HTML encode and optionally URL encode
        return [
            PayloadEncoder.html_encode(payload),
            PayloadEncoder.url_encode(PayloadEncoder.html_encode(payload))
        ]
    return payload

def get_waf_bypass_encodings(payload):
    """Generate WAF bypass encoding variations"""
    encoder = PayloadEncoder()
    bypass_encodings = []
    
    # Basic encoding variations
    bypass_encodings.extend([
        encoder.url_encode(payload),
        encoder.url_encode(payload, double=True),
        encoder.unicode_encode(payload)
    ])
    
    # Mixed encoding variations
    bypass_encodings.extend([
        encoder.url_encode(encoder.html_encode(payload)),
        encoder.unicode_encode(encoder.url_encode(payload)),
        encoder.base64_encode(encoder.url_encode(payload))
    ])
    
    # Add some special cases for WAF bypass
    special_chars = {
        '<': '%3C',
        '>': '%3E',
        '"': '%22',
        '\'': '%27',
        '(': '%28',
        ')': '%29'
    }
    
    # Create variations with special character encoding
    special_encoded = payload
    for char, encoded in special_chars.items():
        special_encoded = special_encoded.replace(char, encoded)
    bypass_encodings.append(special_encoded)
    
    return bypass_encodings
