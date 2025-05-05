# XSStrike Enhanced Features

## New Capabilities

### 1. Enhanced Payload Groups
- HTML Context Payloads
- Attribute Context Payloads
- Script Context Payloads
- Template Injection Payloads
- Prototype Pollution Payloads

### 2. Advanced Encoding Support
The enhanced version includes sophisticated encoding mechanisms to bypass security controls:

#### Supported Encodings:
- HTML Encoding
- URL Encoding (Single and Double)
- Base64 Encoding
- Unicode Encoding
- Mixed Encodings
- WAF Bypass Encodings

#### Context-Aware Encoding:
Different contexts receive appropriate encoding:
- HTML Context: HTML encoding
- Script Context: JavaScript string escaping
- Attribute Context: Combined HTML/URL encoding
- Template Context: Multiple encoding variations

### 3. Template Injection Detection
Automatically detects and tests for template injection vulnerabilities:
- Angular/Vue.js style ({{expression}})
- JavaScript template literals (${expression})
- Server-side templates ({%expression%})

### 4. Prototype Pollution Detection
Includes specialized detection and exploitation of prototype pollution vulnerabilities:
- Object prototype chain attacks
- Constructor pollution
- Framework-specific pollution vectors

## Usage

### Basic Scan with Enhanced Features
```bash
python xsstrike.py -u "http://example.com/?param=value"
```
The scanner will automatically:
1. Detect the context of injection points
2. Apply appropriate encodings
3. Test for template injection
4. Check for prototype pollution
5. Generate context-aware payloads

### WAF Bypass
When a WAF is detected, the scanner automatically:
- Applies multiple encoding layers
- Uses specialized WAF bypass payloads
- Tests different encoding combinations

## New Files Added

### core/payload_groups.py
Organizes payloads by context and attack type:
- HTML context payloads
- Attribute context payloads
- Script context payloads
- Template injection payloads
- Prototype pollution payloads

### core/encoders_enhanced.py
Provides advanced encoding capabilities:
- Multiple encoding methods
- Context-aware encoding
- WAF bypass techniques
- Mixed encoding strategies

### core/template_handler.py
Handles template injection detection and exploitation:
- Template syntax detection
- Context-specific payload generation
- Framework detection
- Exploitation techniques

### core/fuzzer_enhanced.py
Enhanced fuzzing capabilities:
- Context-aware payload generation
- Automatic encoding selection
- WAF bypass attempts
- Template and prototype pollution testing

## Best Practices

1. **Context Analysis**
   - Always analyze the injection context
   - Use appropriate encoding for the context
   - Consider framework-specific escaping rules

2. **WAF Bypass**
   - Start with simple payloads
   - Gradually increase encoding complexity
   - Monitor WAF responses
   - Use mixed encoding when needed

3. **Template Injection**
   - Check for template syntax
   - Identify the template engine
   - Use engine-specific payloads
   - Test different syntax variations

4. **Prototype Pollution**
   - Check JavaScript framework usage
   - Test constructor pollution
   - Verify object prototype chain
   - Use framework-specific vectors

## Contributing

To add new payloads or encodings:

1. Add payloads to appropriate groups in `payload_groups.py`
2. Add new encoding methods to `encoders_enhanced.py`
3. Update fuzzing logic in `fuzzer_enhanced.py`
4. Test thoroughly with different contexts
5. Document new additions

## Future Enhancements

Planned improvements:
1. More framework-specific payloads
2. Advanced WAF bypass techniques
3. Automated framework detection
4. Enhanced reporting capabilities
5. Integration with other security tools
