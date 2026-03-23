# LAB-04: Deliberately Vulnerable Dockerfile
# Tests: root user, mutable tag, exposed secrets, dangerous practices
# DO NOT BUILD in production — for skill testing only

FROM ubuntu:latest

# VULN: running apt-get without pinned versions
RUN apt-get update && apt-get install -y curl wget netcat ssh

# VULN: secret in ENV layer (persists in image history)
ENV DB_PASSWORD="super_secret_prod_password"
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
ENV API_KEY="sk-prod-1234567890abcdef"

# VULN: copying entire context including .git, .env, secrets
COPY . /app

WORKDIR /app

# VULN: running as root (no USER directive)
RUN pip install -r requirements.txt

# VULN: downloading and executing remote script
RUN curl https://get.example.com/install.sh | bash

# VULN: SSH exposed
EXPOSE 22
EXPOSE 8080

# VULN: no HEALTHCHECK
CMD ["python", "app.py"]
