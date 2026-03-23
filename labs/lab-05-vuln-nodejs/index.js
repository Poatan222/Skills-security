// LAB-05: Deliberately Vulnerable Node.js / Express App
// Tests: SQLi, path traversal, command injection, insecure deserialization
// DO NOT DEPLOY — for skill testing only

const express = require('express');
const mysql = require('mysql');
const fs = require('fs');
const { exec } = require('child_process');
const serialize = require('node-serialize');

const app = express();
app.use(express.json());

// VULN: hardcoded credentials
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password123',          // hardcoded DB password
  database: 'myapp'
});

// VULN: SQL injection — string concatenation in query
app.get('/users', (req, res) => {
  const name = req.query.name;
  const query = "SELECT * FROM users WHERE name = '" + name + "'";
  db.query(query, (err, results) => res.json(results));
});

// VULN: Path traversal — unsanitized file path
app.get('/file', (req, res) => {
  const filename = req.query.name;
  const content = fs.readFileSync('/var/www/files/' + filename, 'utf8');
  res.send(content);
  // Attack: ?name=../../../etc/passwd
});

// VULN: Command injection — user input in exec()
app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec('ping -c 1 ' + host, (err, stdout) => res.send(stdout));
  // Attack: ?host=; cat /etc/passwd
});

// VULN: Insecure deserialization
app.post('/restore', (req, res) => {
  const data = req.body.data;
  const obj = serialize.unserialize(data);  // RCE if data is crafted
  res.json({ status: 'restored', obj });
});

// VULN: No rate limiting on sensitive endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.query(`SELECT * FROM users WHERE username='${username}' AND password='${password}'`,
    (err, results) => {
      if (results.length > 0) res.json({ token: 'jwt-token-here' });
      else res.status(401).json({ error: 'Invalid credentials' });
    }
  );
});

app.listen(3000);
