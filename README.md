# Nexus

## Overview

Nexus is a modern enterprise application platform designed to provide a scalable, maintainable, and secure foundation for business applications.

The project follows a modern full-stack architecture consisting of:

* Angular frontend
* Spring Boot backend
* Relational database layer
* Automated CI/CD quality pipeline
* Enterprise-grade development standards

---

# Architecture

```text
┌─────────────────────┐
│     Frontend        │
│      Angular        │
└──────────┬──────────┘
           │ REST API
           ▼
┌─────────────────────┐
│      Backend        │
│    Spring Boot      │
└──────────┬──────────┘
           │ JPA
           ▼
┌─────────────────────┐
│      Database       │
│       MySQL         │
└─────────────────────┘
```

---

# Technology Stack

| Layer                 | Technology      | Version                |
| --------------------- | --------------- | ---------------------- |
| Frontend              | Angular         | Latest                 |
| Frontend Language     | TypeScript      | Latest                 |
| Frontend Styling      | SCSS            | Latest                 |
| Backend               | Spring Boot     | 4.0.6                  |
| Backend Language      | Java            | 25                     |
| ORM                   | Spring Data JPA | Managed by Spring Boot |
| Database              | MySQL           | Runtime Driver         |
| Test Database         | H2              | Latest                 |
| Build Tool            | Maven           | Latest                 |
| CI/CD                 | GitHub Actions  | Latest                 |
| Code Coverage         | JaCoCo          | 0.8.13                 |
| Static Analysis       | SpotBugs        | 4.9.4.1                |
| Style Validation      | Checkstyle      | 3.6.0                  |
| Boilerplate Reduction | Lombok          | Latest                 |

---

# Frontend

## Application

**Project Name**

```text
nexus-frontend
```

## Technology

* Angular
* TypeScript
* SCSS
* NPM

## Configuration

| Property         | Value                 |
| ---------------- | --------------------- |
| Default Port     | 2000                  |
| Styling          | SCSS                  |
| Package Manager  | NPM                   |
| Source Root      | src                   |
| Production Build | Enabled               |
| Source Maps      | Enabled (Development) |

## Frontend Structure

```text
nexus-frontend/
├── src/
├── public/
├── angular.json
├── package.json
└── tsconfig*.json
```

## Frontend Commands

### Install Dependencies

```bash
npm install
```

### Start Development Server

```bash
npm start
```

or

```bash
ng serve
```

Application URL:

```text
http://localhost:2000
```

### Production Build

```bash
ng build --configuration production
```

---

# Backend

## Application

**Project Name**

```text
nexus-backend
```

## Technology

* Spring Boot 4.0.6
* Java 25
* Spring Data JPA
* Hibernate
* Maven
* Lombok

## Backend Structure

```text
nexus-backend/
├── src/
│   ├── main/
│   └── test/
├── pom.xml
└── mvnw
```

## Backend Commands

### Build

```bash
mvn clean package
```

### Run Tests

```bash
mvn test
```

### Verify Build

```bash
mvn clean verify
```

### Run Application

```bash
mvn spring-boot:run
```

---

# Database

## Primary Database

### MySQL

Used for:

* Application data
* Transactional workloads
* Production environments

### Connectivity

Configured through Spring Boot datasource configuration.

Example:

```yaml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/nexus
    username: nexus
    password: password
```

---

## Test Database

### H2

Used for:

* Unit tests
* Integration tests
* CI/CD pipelines

Benefits:

* Fast startup
* In-memory execution
* No external infrastructure dependency

---

# Quality Engineering

## Automated Testing

The project includes:

* Unit Tests
* Spring Context Tests
* Repository Tests
* Integration Tests

---

## Code Coverage

### JaCoCo

Provides:

* Line Coverage
* Branch Coverage
* Method Coverage

Generated during:

```bash
mvn verify
```

Report Location:

```text
target/site/jacoco
```

---

## Static Code Analysis

### SpotBugs

Detects:

* Potential bugs
* Null pointer risks
* Resource leaks
* Bad coding practices

Executed during:

```bash
mvn verify
```

---

## Code Style Validation

### Checkstyle

Based on:

```text
Google Java Style Guide
```

Provides:

* Consistent formatting
* Naming convention validation
* Code style enforcement

---

# DevOps

## Continuous Integration

GitHub Actions is used to automate validation and quality checks.

### Trigger Conditions

```text
Push:
  - main
  - feature/**

Pull Requests:
  - main
```

---

## CI Pipeline Flow

### Frontend CI

```text
Developer Push
       │
       ▼
Checkout Source
       │
       ▼
Setup Node.js 24
       │
       ▼
NPM Install (npm ci)
       │
       ▼
Angular Production Build
       │
       ├── TypeScript Compilation
       ├── Template Validation
       ├── Dependency Resolution
       └── Production Bundle Generation
       │
       ▼
Upload Build Artifact
       │
       ▼
Build Complete
```

---

### Backend CI

```text
Developer Push
       │
       ▼
Checkout Source
       │
       ▼
Setup JDK 25
       │
       ▼
Maven Clean Verify
       │
       ├── Compile
       │
       ├── Execute Tests
       │
       ├── H2 Test Database
       │
       ├── Checkstyle
       │
       ├── SpotBugs
       │
       ├── JaCoCo Coverage
       │
       └── Package Application
       │
       ▼
Upload Reports
       │
       ├── Test Results
       ├── JaCoCo Report
       └── SpotBugs Report
       │
       ▼
Build Complete
```

---

### Quality Gates

| Area                    | Frontend              | Backend                       |
| ----------------------- | --------------------- | ----------------------------- |
| Dependency Installation | ✅ npm ci              | ✅ Maven Dependency Resolution |
| Compilation             | ✅ Angular Build       | ✅ Java Compilation            |
| Testing                 | ⏳ Planned (Vitest)    | ✅ JUnit / Spring Tests        |
| Code Coverage           | ⏳ Planned             | ✅ JaCoCo                      |
| Static Analysis         | ⏳ Planned             | ✅ SpotBugs                    |
| Style Validation        | ⏳ Planned             | ✅ Checkstyle                  |
| Artifact Generation     | ✅ Angular Dist Bundle | ✅ Spring Boot JAR             |
| CI Platform             | ✅ GitHub Actions      | ✅ GitHub Actions              |


---

# Future Roadmap

Planned enhancements include:

* CodeQL Security Analysis
* OWASP Dependency Check
* SonarQube Integration
* Containerization
* Kubernetes Deployment
* Infrastructure as Code
* Automated Release Pipelines
* Security Scanning
* Performance Testing
* Multi-Tenant Architecture

---

# License

Proprietary - Internal Use Only.

