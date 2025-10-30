# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Spring Boot 3.5.6 application built with Java 21 using Gradle. This is a user authentication system with login, signup, and password recovery features. The application uses:
- **Spring Data JPA** with H2 database for data persistence
- **Mustache** templating engine for server-side rendering
- **Lombok** for reducing boilerplate code
- **Spring Web MVC** for HTTP request handling
- **Jakarta Validation** for server-side form validation

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
- **`com.example.demo.controller`**: HTTP request handlers (`Login`, `Signup`, `FindID`, `FindPW`)
- **`com.example.demo.dto`**: Data Transfer Objects for form binding and validation (`LoginRequest`, `SignupRequest`, `FindIDRequest`, `FindPWRequest`)

Future service layer classes should go in `com.example.demo.service`.
Future repository interfaces should go in `com.example.demo.repository`.
Future entity classes should go in `com.example.demo.entity`.

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

### Data Transfer Objects (DTOs)
All DTOs are Lombok-annotated POJOs with Jakarta validation constraints:
- **`LoginRequest`**: User login form with `id`, `pw`, `name`, `email`, `personalNumber` fields
- **`SignupRequest`**: User signup form with the same fields as `LoginRequest`
- **`FindIDRequest`**: ID recovery form
- **`FindPWRequest`**: Password recovery form

Each field uses `@NotBlank` validation with Korean error messages. DTOs are currently used for form binding but data is not yet persisted to H2 database.

## Key Technologies

### Java 21
The project uses Java 21 language features. Gradle toolchain enforces this version.

### Lombok
All DTOs use Lombok annotations (`@Getter`, `@Setter`, `@NoArgsConstructor`, `@AllArgsConstructor`). When creating new DTOs or entities, follow the pattern in existing DTO classes.

### Jakarta Validation
Form validation uses Jakarta Validation API (`@Valid`, `@NotBlank`, etc.). All controller methods handling forms should:
1. Use `@Valid` annotation on `@ModelAttribute` parameters
2. Include `BindingResult` parameter to capture validation errors
3. Return to the same form view when `bindingResult.hasErrors()` is true

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
Both authentication endpoints need REST API integration:
- `Login.tryLogin()` at `controller/Login.java:24` - returns empty string after validation
- `Signup.SignupUserAccount()` at `controller/Signup.java:17` - has comments outlining needed implementation (REST API call and result rendering)

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
