# Union Based SQLi 

<h3> SQL injection UNION attacks </h3>

When an application is vulnerable to SQL injection and the results of the query are returned within the application's responses, the UNION keyword can be used to retrieve data from other tables within the database. This results in a SQL injection UNION attack.

The UNION keyword lets you execute one or more additional SELECT queries and append the results to the original query. For example:

```sql
SELECT a, b FROM table1 UNION SELECT c, d FROM table2
```

This SQL query will return a single result set with two columns, containing values from columns a and b in table1 and columns c and d in table2.

For a UNION query to work, two key requirements must be met:

The individual queries must return the same number of columns.
The data types in each column must be compatible between the individual queries.
To carry out a SQL injection UNION attack, you need to ensure that your attack meets these two requirements. This generally involves figuring out:

How many columns are being returned from the original query?
Which columns returned from the original query are of a suitable data type to hold the results from the injected query?
Determining the number of columns required in a SQL injection UNION attack
When performing a SQL injection UNION attack, there are two effective methods to determine how many columns are being returned from the original query.

The first method involves injecting a series of ORDER BY clauses and incrementing the specified column index until an error occurs. For example, assuming the injection point is a quoted string within the WHERE clause of the original query, you would submit:

```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
etc.
```

This series of payloads modifies the original query to order the results by different columns in the result set. The column in an ORDER BY clause can be specified by its index, so you don't need to know the names of any columns. When the specified column index exceeds the number of actual columns in the result set, the database returns an error, such as:

The ORDER BY position number 3 is out of range of the number of items in the select list.
The application might actually return the database error in its HTTP response, or it might return a generic error, or simply return no results. Provided you can detect some difference in the application's response, you can infer how many columns are being returned from the query.

The second method involves submitting a series of UNION SELECT payloads specifying a different number of null values:

```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
etc.
```

If the number of nulls does not match the number of columns, the database returns an error, such as:

All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.
Again, the application might actually return this error message, or might just return a generic error or no results. When the number of nulls matches the number of columns, the database returns an additional row in the result set, containing null values in each column. The effect on the resulting HTTP response depends on the application's code. If you are lucky, you will see some additional content within the response, such as an extra row on an HTML table. Otherwise, the null values might trigger a different error, such as a NullPointerException. Worst case, the response might be indistinguishable from that which is caused by an incorrect number of nulls, making this method of determining the column count ineffective.

<h3> Finding columns with a useful data type in a SQL injection UNION attack </h3>

The reason for performing a SQL injection UNION attack is to be able to retrieve the results from an injected query. Generally, the interesting data that you want to retrieve will be in string form, so you need to find one or more columns in the original query results whose data type is, or is compatible with, string data.

Having already determined the number of required columns, you can probe each column to test whether it can hold string data by submitting a series of UNION SELECT payloads that place a string value into each column in turn. For example, if the query returns four columns, you would submit:

```sql
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```

If the data type of a column is not compatible with string data, the injected query will cause a database error, such as:

Conversion failed when converting the varchar value 'a' to data type int.
If an error does not occur, and the application's response contains some additional content including the injected string value, then the relevant column is suitable for retrieving string data.
