# Java / Spring Boot — Insecure Patterns

Framework-specific vulnerabilities, dangerous defaults, and common developer mistakes in Spring Boot applications.

## Dangerous Defaults and Configurations

### Actuator Exposure

```java
// application.properties — DANGEROUS if exposed to internet
management.endpoints.web.exposure.include=*
management.endpoint.env.show-values=ALWAYS

// Actuator endpoints leak: environment variables (secrets), heap dumps,
// thread dumps, beans, conditions, scheduled tasks, HTTP trace
```

**What to look for:** Actuator endpoints accessible without authentication. Check `SecurityFilterChain` excludes actuator paths.

### Debug Mode in Production

```yaml
# DANGEROUS
logging.level.org.springframework.security: DEBUG
spring.jpa.show-sql: true
server.error.include-stacktrace: always
server.error.include-message: always
```

### CORS Misconfiguration

```java
// DANGEROUS: allows any origin
@CrossOrigin(origins = "*")

// DANGEROUS: reflects Origin header
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.addAllowedOrigin("*");
    config.setAllowCredentials(true);  // This + wildcard = credential theft
}
```

## SQL Injection Patterns

### Raw JDBC with String Concatenation

```java
// VULNERABLE
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);

// VULNERABLE — JdbcTemplate with string concat
jdbcTemplate.query("SELECT * FROM users WHERE name = '" + name + "'",
    new UserRowMapper());
```

### JPA/Hibernate Native Queries

```java
// VULNERABLE — native query with string concat
@Query(value = "SELECT * FROM users WHERE name = " + name, nativeQuery = true)
List<User> findByName(@Param("name") String name);

// VULNERABLE — createNativeQuery with concat
em.createNativeQuery("SELECT * FROM users WHERE role = '" + role + "'");

// SAFE — parameterized
@Query("SELECT u FROM User u WHERE u.name = :name")
List<User> findByName(@Param("name") String name);
```

### Criteria API Misuse

```java
// VULNERABLE — string concat in Criteria
CriteriaBuilder cb = em.getCriteriaBuilder();
Predicate p = cb.like(root.get("name"), "%" + userInput + "%");
// If userInput contains SQL wildcards, it's a DoS vector
```

## Authentication and Authorization

### SpEL Injection in @PreAuthorize

```java
// VULNERABLE — user input in SpEL expression
@PreAuthorize("#oauth2.hasScope('" + userProvidedScope + "')")

// DANGEROUS — overly permissive
@PreAuthorize("permitAll()")  // On sensitive endpoints

// COMMON MISTAKE — method security not enabled
// @EnableGlobalMethodSecurity missing from config
// All @PreAuthorize annotations silently ignored
```

**Check:** Is `@EnableMethodSecurity` (Spring 6+) or `@EnableGlobalMethodSecurity` present in a `@Configuration` class?

### Security Filter Chain Ordering

```java
// DANGEROUS — permit all before authenticated
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/**").permitAll()    // This matches everything first!
    .requestMatchers("/admin/**").hasRole("ADMIN")  // Never reached
);

// DANGEROUS — missing default deny
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/public/**").permitAll()
    .requestMatchers("/admin/**").hasRole("ADMIN")
    // Missing: .anyRequest().authenticated() — new endpoints are unprotected
);
```

### Path Matching Confusion

```java
// Spring's path matching can differ from security filter matching

// VULNERABLE — trailing slash bypass
// Security config protects "/admin" but not "/admin/"
.requestMatchers("/admin").hasRole("ADMIN")
// Attacker accesses /admin/ — bypasses check

// VULNERABLE — case sensitivity
// "/Admin" vs "/admin" on case-insensitive configs

// VULNERABLE — path traversal in URL
// "/public/../admin/users" may bypass the filter but resolve to admin endpoint
```

## Deserialization

```java
// CRITICAL — Java deserialization from untrusted input
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();  // Remote Code Execution if classpath has gadget chains

// Also check for:
// - XMLDecoder with untrusted input
// - SnakeYAML with untrusted input (pre-2.0)
// - Jackson with enableDefaultTyping() or @JsonTypeInfo
```

### Jackson Polymorphic Deserialization

```java
// VULNERABLE — enables type in JSON, allowing arbitrary class instantiation
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();  // CRITICAL VULNERABILITY

// VULNERABLE — annotation on class
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
public class Message { ... }
// Attacker sends: {"@class": "dangerous.Gadget", ...}
```

## SSRF via RestTemplate / WebClient

```java
// VULNERABLE — user-controlled URL
String url = request.getParameter("url");
RestTemplate restTemplate = new RestTemplate();
String result = restTemplate.getForObject(url, String.class);

// ALSO CHECK: WebClient, HttpClient, URL.openConnection()
```

## File Operations

```java
// VULNERABLE — path traversal
String filename = request.getParameter("file");
Path path = Paths.get("/uploads/" + filename);  // ../../etc/passwd
Files.readAllBytes(path);

// SAFE — resolve and check
Path basePath = Paths.get("/uploads/").toRealPath();
Path resolved = basePath.resolve(filename).normalize().toRealPath();
if (!resolved.startsWith(basePath)) {
    throw new SecurityException("Path traversal detected");
}
```

## Mass Assignment

```java
// VULNERABLE — binds all request params to entity
@PostMapping("/users")
public User createUser(@RequestBody User user) {
    return userRepository.save(user);  // Attacker can set role, isAdmin, etc.
}

// SAFE — use DTO with only allowed fields
@PostMapping("/users")
public User createUser(@RequestBody @Valid CreateUserDTO dto) {
    User user = new User();
    user.setName(dto.getName());
    user.setEmail(dto.getEmail());
    // role is NOT set from input
    return userRepository.save(user);
}
```

## Logging Sensitive Data

```java
// VULNERABLE — logging passwords, tokens, PII
log.info("Login attempt for user {} with password {}", username, password);
log.debug("Request: {}", request.getBody());  // May contain secrets
log.info("Token: {}", authToken);
```
