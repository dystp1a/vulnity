# Injection - SQL

## Description
SQL injection happens when untrusted input is concatenated into a SQL query
string instead of being passed as a parameter. An attacker can change the
structure of the query to read, modify, or delete data outside the
application's intended access, or in some drivers chain additional statements.

## Why it happens in Node.js / Express apps
Common root causes: building queries with string concatenation or template
literals (`` `SELECT * FROM users WHERE id = ${id}` ``), using an ORM's raw
query escape hatch without parameter binding, or trusting input that has
already passed client-side validation.

## Remediation
- Always use parameterized queries / prepared statements. With `mysql2`,
  `pg`, or `sqlite3`, pass values as a second argument array rather than
  interpolating them into the SQL string.
- If using an ORM (Sequelize, TypeORM, Prisma), use its query builder or
  parameter binding APIs instead of `.raw()` / literal SQL with concatenation.
- Apply least privilege to the database account the app uses — it should not
  be able to read tables or run commands it doesn't need.
- Add input validation as defense-in-depth, but never as the only control;
  validation can be bypassed and is not a substitute for parameterization.

## Verification
After patching, confirm the fix by sending a single-quote or boolean-based
payload to the same input and confirming the query no longer errors or
returns unintended rows.
