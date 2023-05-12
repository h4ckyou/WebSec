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

<h3> Listing the contents of the database </h3>

Most database types (with the notable exception of Oracle) have a set of views called the information schema which provide information about the database.

You can query information_schema.tables to list the tables in the database:

```sql
SELECT * FROM information_schema.tables
```

This returns output like the following:

TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  TABLE_TYPE
=====================================================
MyDatabase     dbo           Products    BASE TABLE
MyDatabase     dbo           Users       BASE TABLE
MyDatabase     dbo           Feedback    BASE TABLE
This output indicates that there are three tables, called Products, Users, and Feedback.

You can then query information_schema.columns to list the columns in individual tables:

```sql
SELECT * FROM information_schema.columns WHERE table_name = 'Users'
```

This returns output like the following:

TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  COLUMN_NAME  DATA_TYPE
=================================================================
MyDatabase     dbo           Users       UserId       int
MyDatabase     dbo           Users       Username     varchar
MyDatabase     dbo           Users       Password     varchar
This output shows the columns in the specified table and the data type of each column.
