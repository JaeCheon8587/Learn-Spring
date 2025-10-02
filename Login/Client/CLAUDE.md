# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Spring Boot 3.5.6 application built with Java 21 using Gradle. This is a user authentication system with login, signup, and password recovery features. The application uses:
- **Spring Data JPA** with H2 database for data persistence
- **Mustache** templating engine for server-side rendering
- **Lombok** for reducing boilerplate code
- **Spring Web MVC** for HTTP request handling

## Development Commands

### Running the Application
```bash
./gradlew bootRun
```
Launches the Spring Boot application with embedded server on the default port (8080).

### Building
```bash
./gradlew build
```
Compiles, runs tests, and produces the executable JAR in `build/libs/`.

### Testing
```bash
# Run all tests
./gradlew test

# Run a specific test class
./gradlew test --tests com.example.demo.DemoApplicationTests

# Clean build artifacts before testing
./gradlew clean test
```

### Cleaning
```bash
./gradlew clean
```
Removes all compiled output from `build/` directory.

## Architecture

### Package Structure
- **`com.example.demo`**: Root package containing `DemoApplication` (Spring Boot entry point)
- **`com.example.demo.controller`**: HTTP request handlers (e.g., `Login`, `SingUp`)
- **`com.example.demo.data`**: Data models and DTOs (e.g., `UserAccount`)

Future service layer classes should go in `com.example.demo.service`.
Future repository interfaces should go in `com.example.demo.repository`.

### Current Controllers
The `Login` controller (`controller/Login.java`) handles authentication-related GET routes:
- `GET /Login` → renders Login.mustache
- `POST /Login/UserAccount` → processes login (currently incomplete - needs REST API integration)
- `GET /Signup` → renders Signup.mustache
- `GET /FindID` → renders FindID.mustache
- `GET /FindPW` → renders FindPW.mustache

The `Signup` controller (`controller/Signup.java`) handles signup POST operations:
- `POST /Signup/UserAccount` → processes signup (currently incomplete - needs REST API integration and result rendering)

### Templates
Mustache templates are in `src/main/resources/templates/`:
- `Login.mustache`, `Signup.mustache`, `FindID.mustache`, `FindPW.mustache`

Each controller method returning a String corresponds to a template name.

### Data Model
`UserAccount` is a Lombok-annotated POJO with `id` and `pw` fields. Currently used for form binding but not yet persisted to H2 database.

## Key Technologies

### Java 21
The project uses Java 21 language features. Gradle toolchain enforces this version.

### Lombok
All data classes use Lombok annotations (`@Getter`, `@Setter`, `@AllArgsConstructor`, etc.). When creating new models, follow the pattern in `UserAccount.java`.

### Spring Boot Auto-configuration
The application relies heavily on Spring Boot's auto-configuration. The H2 database is configured automatically; explicit datasource configuration can be added to `application.properties` if needed.

### Mustache Templating
Server-side rendering uses Mustache. Controller methods return template names (without `.mustache` extension). Model data is passed via `Model` or `ModelAndView` objects.

## Code Conventions

### Naming
- **Classes/Components**: PascalCase (e.g., `LoginController`)
- **Methods/Fields**: camelCase (e.g., `accessLogin`, `tryLogin`)
- **Template Files**: TitleCase (e.g., `Login.mustache`)

### Indentation
Tab-based indentation is used throughout. Maintain this convention.

### Dependency Injection
Use constructor injection for Spring beans. Keep controllers thin; business logic should be delegated to service layer classes.

## Testing Guidelines

- Tests are in `src/test/java/com/example/demo/`
- Test class names should match the class under test with a `Tests` suffix (e.g., `DemoApplicationTests`)
- Use `@WebMvcTest` for controller tests (lightweight)
- Use `@SpringBootTest` only when full application context is needed
- All tests use JUnit 5 (Jupiter)

## Important Notes

### Incomplete Implementation
The `Login.tryLogin()` method at `controller/Login.java:19` has a TODO comment indicating REST API integration is needed. This endpoint currently returns an empty string.

### File Naming Issue
`SingUp.Java` should be renamed to `SignUp.java` for consistency with Java naming conventions.

### No Service Layer Yet
Currently controllers directly handle business logic. As the application grows, introduce a service layer between controllers and repositories.

### H2 Database
The application uses an in-memory H2 database. Data is lost on application restart. Configure H2 console in `application.properties` for debugging:
```properties
spring.h2.console.enabled=true
spring.datasource.url=jdbc:h2:mem:testdb
```

## Reference Documentation
See `HELP.md` for Spring Boot official documentation links.
See `AGENTS.md` for detailed repository guidelines on commit conventions, PR requirements, and coding style.
