# Node.js / Express — Insecure Patterns

Framework-specific vulnerabilities, dangerous defaults, and common developer mistakes.

## Dangerous Configurations

### Express Settings

```javascript
// DANGEROUS — detailed errors in production
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack }); // Leaks internals
});

// DANGEROUS — trust proxy without validation
app.set('trust proxy', true);
// Attacker can spoof X-Forwarded-For to bypass IP-based restrictions

// MISSING — security headers
// Check if helmet middleware is present and configured
// Without it: missing X-Frame-Options, CSP, HSTS, etc.
```

### CORS Misconfiguration

```javascript
// DANGEROUS — reflect origin
const cors = require('cors');
app.use(cors({
  origin: true,           // Reflects any Origin
  credentials: true       // Combined = credential theft
}));

// DANGEROUS — regex that's too permissive
app.use(cors({
  origin: /example\.com/  // Matches evil-example.com too!
}));

// SAFE
app.use(cors({
  origin: ['https://app.example.com'],
  credentials: true
}));
```

## Injection Vulnerabilities

### SQL Injection (with raw queries)

```javascript
// VULNERABLE — string concatenation
const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
db.query(query);

// VULNERABLE — template literal
db.query(`SELECT * FROM users WHERE name = '${req.body.name}'`);

// SAFE — parameterized
db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);

// Sequelize VULNERABLE — raw query with interpolation
sequelize.query(`SELECT * FROM users WHERE name = '${name}'`);

// Sequelize SAFE
sequelize.query('SELECT * FROM users WHERE name = ?', {
  replacements: [name], type: QueryTypes.SELECT
});
```

### NoSQL Injection (MongoDB)

```javascript
// VULNERABLE — req.body passed directly to query
app.post('/login', async (req, res) => {
  const user = await User.findOne({
    username: req.body.username,   // Can be {"$gt": ""}
    password: req.body.password    // Can be {"$gt": ""}
  });
  if (user) { /* authenticated */ }
});
// Attacker sends: {"username": {"$gt": ""}, "password": {"$gt": ""}}
// Matches first user in collection (usually admin)

// VULNERABLE — $where with user input
User.find({ $where: `this.username == '${username}'` });
// This is JavaScript execution in MongoDB — injection possible

// SAFE — validate types before querying
if (typeof req.body.username !== 'string') return res.status(400).send('Invalid');
const user = await User.findOne({ username: req.body.username });
```

### Command Injection

```javascript
// VULNERABLE
const { exec } = require('child_process');
exec(`ping ${req.query.host}`, (error, stdout) => {
  res.send(stdout);
});
// Attacker: ?host=127.0.0.1;cat /etc/passwd

// ALSO VULNERABLE
exec('convert ' + req.file.path + ' output.png');

// SAFE — use execFile (no shell)
const { execFile } = require('child_process');
execFile('ping', ['-c', '1', validatedHost], (error, stdout) => {
  res.send(stdout);
});
```

### Prototype Pollution

```javascript
// VULNERABLE — deep merge without protection
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object') {
      target[key] = merge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
// Attacker sends: {"__proto__": {"isAdmin": true}}
// Now ALL objects have isAdmin = true

// ALSO CHECK: lodash.merge (pre-4.17.12), jQuery.extend (deep), Object.assign

// SAFE — block dangerous keys
const BLOCKED_KEYS = ['__proto__', 'constructor', 'prototype'];
function safeMerge(target, source) {
  for (const key in source) {
    if (BLOCKED_KEYS.includes(key)) continue;
    // ... rest of merge
  }
}
```

### Server-Side Template Injection

```javascript
// VULNERABLE — EJS with user input in template
const ejs = require('ejs');
const template = `<h1>Hello ${req.query.name}</h1>`;
res.send(ejs.render(template));

// VULNERABLE — Pug/Jade with user-controlled template
const pug = require('pug');
const fn = pug.compile(req.body.template);  // Attacker controls template

// SAFE — pass user input as data, not template
res.render('hello', { name: req.query.name });
```

## Authentication and Authorization

### JWT Issues

```javascript
// VULNERABLE — not verifying signature
const decoded = jwt.decode(token);  // decode != verify!
// SAFE:
const decoded = jwt.verify(token, secret);

// VULNERABLE — weak secret
jwt.sign(payload, 'secret123');

// VULNERABLE — not checking expiration
jwt.verify(token, secret, { ignoreExpiration: true });

// VULNERABLE — accepting algorithm from token header
jwt.verify(token, publicKey);  // If attacker changes alg to HS256, signs with publicKey
// SAFE:
jwt.verify(token, publicKey, { algorithms: ['RS256'] });
```

### Missing Auth Middleware

```javascript
// COMMON PATTERN — auth middleware defined but not applied to all routes
app.get('/api/public', publicHandler);
app.get('/api/users', authMiddleware, usersHandler);
app.get('/api/admin/settings', settingsHandler);  // MISSING authMiddleware!

// CHECK: Is there a catch-all? Or must every route explicitly add middleware?

// ALSO CHECK: Route ordering
app.get('/api/users/:id', authMiddleware, getUser);
app.get('/api/users/export', exportUsers);  // Matches before :id but no auth!
```

### IDOR

```javascript
// VULNERABLE — no ownership check
app.get('/api/orders/:id', auth, async (req, res) => {
  const order = await Order.findById(req.params.id);  // Any authenticated user
  res.json(order);
});

// SAFE
app.get('/api/orders/:id', auth, async (req, res) => {
  const order = await Order.findOne({
    _id: req.params.id,
    userId: req.user.id  // Ownership check
  });
  if (!order) return res.status(404).send();
  res.json(order);
});
```

## Path Traversal

```javascript
// VULNERABLE
app.get('/files/:name', (req, res) => {
  res.sendFile(path.join(__dirname, 'uploads', req.params.name));
  // Attacker: /files/../../etc/passwd
});

// SAFE — resolve and validate
const safePath = path.resolve(uploadDir, req.params.name);
if (!safePath.startsWith(path.resolve(uploadDir))) {
  return res.status(400).send('Invalid path');
}
res.sendFile(safePath);
```

## SSRF

```javascript
// VULNERABLE
const axios = require('axios');
app.post('/api/fetch', async (req, res) => {
  const response = await axios.get(req.body.url);  // Arbitrary URL
  res.json(response.data);
});

// ALSO CHECK: node-fetch, http.get, https.get, got, request
// Any HTTP client where URL comes from user input
```

## Deserialization and eval

```javascript
// CRITICAL — eval with user input
eval(req.query.expr);

// CRITICAL — new Function with user input
const fn = new Function('return ' + req.body.code);

// DANGEROUS — vm module is NOT a sandbox
const vm = require('vm');
vm.runInNewContext(req.body.code);  // Escapable — NOT secure

// DANGEROUS — require with user input
const module = require(req.query.module);  // Arbitrary module loading

// CHECK: JSON.parse is safe, but check what happens with the parsed data
// If it's used in template rendering, DB queries, or eval — still dangerous
```

## Regex DoS

```javascript
// VULNERABLE — catastrophic backtracking
const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
emailRegex.test(userInput);  // Malicious input causes CPU spike

// Node.js regex runs on the event loop — ReDoS blocks ALL requests
// This is more severe in Node than in multi-threaded frameworks

// CHECK: Any regex with nested quantifiers applied to user input
```

## Event Loop Blocking

```javascript
// DANGEROUS — synchronous operations in request handlers
app.get('/api/data', (req, res) => {
  const data = fs.readFileSync(hugePath);  // Blocks event loop
  const result = JSON.parse(data);
  // Expensive sync computation on user input = DoS
  crypto.pbkdf2Sync(req.body.password, salt, 1000000, 64, 'sha512');
});
```
