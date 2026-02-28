# Python / Django / Flask — Insecure Patterns

Framework-specific vulnerabilities, dangerous defaults, and common developer mistakes.

## Django

### Dangerous Settings

```python
# settings.py — DANGEROUS in production
DEBUG = True                    # Exposes full stack traces, settings, SQL queries
ALLOWED_HOSTS = ['*']           # Accepts any Host header (Host header injection)
SECRET_KEY = 'hardcoded-key'    # Session forgery, CSRF bypass if leaked

# DANGEROUS CORS settings (django-cors-headers)
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True   # Combined with allow all = credential theft
```

### SQL Injection

```python
# VULNERABLE — raw SQL with string formatting
User.objects.raw("SELECT * FROM auth_user WHERE username = '%s'" % username)

# VULNERABLE — .extra() with string formatting
User.objects.extra(where=["username = '%s'" % username])

# VULNERABLE — RawSQL expression
from django.db.models.expressions import RawSQL
queryset.annotate(val=RawSQL("select col from sometable where othercol = %s" % user_input))

# SAFE — parameterized
User.objects.raw("SELECT * FROM auth_user WHERE username = %s", [username])
User.objects.filter(username=username)  # ORM is safe
```

### XSS via Template Misuse

```python
# VULNERABLE — marking user input as safe
from django.utils.safestring import mark_safe
def render_comment(comment):
    return mark_safe(comment.body)  # User-controlled, now unescaped

# VULNERABLE — |safe filter in template
# template.html
{{ user_input|safe }}

# VULNERABLE — format_html with unescaped variable
from django.utils.html import format_html
format_html("<div>{}</div>", user_input)  # WRONG — use format_html properly
# SAFE:
format_html("<div>{}</div>", user_input)  # Actually safe — format_html escapes args
# VULNERABLE:
format_html("<div>" + user_input + "</div>")  # String concat BEFORE format_html
```

### Authentication Bypass

```python
# VULNERABLE — @login_required on GET but not POST
class UserView(View):
    @method_decorator(login_required)
    def get(self, request):
        return render(request, 'profile.html')

    def post(self, request):  # NO DECORATOR — unprotected!
        return update_profile(request)

# VULNERABLE — custom auth backend accepts empty credentials
class CustomBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None):
        if not username:
            return None
        try:
            user = User.objects.get(username=username)
            return user  # MISSING PASSWORD CHECK
        except User.DoesNotExist:
            return None
```

### IDOR in Views

```python
# VULNERABLE — no ownership check
def get_order(request, order_id):
    order = Order.objects.get(id=order_id)  # Any user can access any order
    return JsonResponse(order.to_dict())

# SAFE — filter by current user
def get_order(request, order_id):
    order = get_object_or_404(Order, id=order_id, user=request.user)
    return JsonResponse(order.to_dict())
```

### Deserialization

```python
# CRITICAL — pickle with untrusted input
import pickle
data = pickle.loads(request.body)  # Remote Code Execution

# CRITICAL — yaml.load without SafeLoader
import yaml
data = yaml.load(request.body)  # RCE via !!python/object
# SAFE:
data = yaml.safe_load(request.body)

# DANGEROUS — eval / exec with user input
eval(request.GET.get('expr'))  # Obviously RCE
exec(user_provided_code)
```

### Command Injection

```python
# VULNERABLE
import os
os.system("ping " + request.GET.get('host'))

import subprocess
subprocess.call("grep " + query + " /var/log/app.log", shell=True)

# SAFE — use list form, no shell
subprocess.run(["ping", "-c", "1", validated_host], shell=False)
```

### Path Traversal

```python
# VULNERABLE
filename = request.GET.get('file')
with open(f'/uploads/{filename}', 'rb') as f:  # ../../etc/passwd
    return HttpResponse(f.read())

# SAFE
import os
base_dir = os.path.realpath('/uploads/')
filepath = os.path.realpath(os.path.join(base_dir, filename))
if not filepath.startswith(base_dir):
    raise PermissionError("Path traversal detected")
```

## Flask

### Flask-Specific Issues

```python
# DANGEROUS — debug mode in production
app.run(debug=True)  # Enables Werkzeug debugger — interactive RCE console

# VULNERABLE — secret key
app.secret_key = 'dev'  # Weak secret = session forgery

# VULNERABLE — SSTI (Server-Side Template Injection)
@app.route('/hello')
def hello():
    template = request.args.get('name', 'World')
    return render_template_string(f"Hello {template}!")
# Attacker sends: ?name={{config.items()}} or {{7*7}}
# SAFE:
    return render_template_string("Hello {{ name }}!", name=template)
```

### Flask Session Manipulation

```python
# Flask sessions are client-side (signed cookies, not encrypted)
# If SECRET_KEY is weak, attacker can forge sessions

# Check: Is session data trusted without server-side validation?
@app.route('/admin')
def admin():
    if session.get('is_admin'):  # Forgeable if secret key is weak
        return render_template('admin.html')
```

### Missing CSRF Protection

```python
# Flask has no built-in CSRF protection
# Check if Flask-WTF or custom CSRF middleware is present
# If not: all state-changing endpoints are vulnerable to CSRF

# ALSO CHECK: Does the API accept both JSON and form data?
# JSON APIs are CSRF-safe only if they enforce Content-Type: application/json
# If the server accepts form-encoded data too, CSRF is possible
```

## Common Python Patterns (Both Frameworks)

### Regex DoS (ReDoS)

```python
import re
# VULNERABLE — catastrophic backtracking
pattern = re.compile(r'^(a+)+$')
pattern.match(user_input)  # "aaaaaaaaaaaaaaaaaaa!" causes exponential time

# Also check: nested quantifiers, alternation with overlap
```

### SSRF

```python
# VULNERABLE
import requests
url = request.GET.get('url')
response = requests.get(url)  # Fetch arbitrary URLs

# Partial fix that's still vulnerable:
if url.startswith('https://'):  # Bypassable: https://evil.com@169.254.169.254/
    response = requests.get(url)
```

### Mass Assignment

```python
# VULNERABLE — Django
user = User(**request.POST.dict())  # Sets ANY field including is_staff, is_superuser
user.save()

# VULNERABLE — spreading request data
user.__dict__.update(request.json)

# SAFE — explicit field assignment
user.name = request.json.get('name')
user.email = request.json.get('email')
user.save()
```
