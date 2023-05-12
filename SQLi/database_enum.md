<h3> Examining the database in SQL injection attacks </h3>

When exploiting SQL injection vulnerabilities, it is often necessary to gather some information about the database itself. This includes the type and version of the database software, and the contents of the database in terms of which tables and columns it contains.

<h3> Querying the database type and version </h3>

Different databases provide different ways of querying their version. You often need to try out different queries to find one that works, allowing you to determine both the type and version of the database software.

The queries to determine the database version for some popular database types are as follows:

```
Database type         Query
Microsoft, MySQL      SELECT @@version
Oracle                SELECT * FROM v$version
PostgreSQL            SELECT version()
```

