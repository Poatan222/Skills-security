# Container Image Remediation

Steps for fixing vulnerabilities in container images.

## Workflow

1. Identify the vulnerable package and which base image layer introduces it
2. Check if a patched base image is available
3. Rebuild image with updated base/package
4. Test in staging
5. Deploy to production
6. Re-scan to confirm remediation

## Common Fixes

### Update Base Image

```dockerfile
# Before (vulnerable)
FROM node:18.15-alpine

# After (patched)
FROM node:18.20-alpine
```

### Pin and Update Specific Package

```dockerfile
# Add to Dockerfile to force package update
RUN apk update && apk upgrade [package-name]
```

### Multi-Stage Build (Minimize Attack Surface)

```dockerfile
FROM node:18-alpine AS build
WORKDIR /app
COPY . .
RUN npm ci && npm run build

FROM node:18-alpine AS runtime
COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules
USER node
CMD ["node", "dist/index.js"]
```

## CI/CD Integration

- Block deployments if image scan finds CRITICAL/HIGH CVEs
- Integrate Trivy, Grype, or Snyk Container into pipeline
- Set policy: no images older than 30 days in production
