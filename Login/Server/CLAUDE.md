# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Spring Boot 3.5.6 application built with Java 21 and Gradle. This is a login server demo project using:
- **Spring Data JPA** with Oracle database (with H2 available for testing)
- **Jakarta Validation** for request validation
- **Mustache** templating engine for views
- **Lombok** for reducing boilerplate code
- Standard Spring Boot web stack

## Build & Development Commands

### Building the Project
```bash
# Build the project
./gradlew build

# Build without tests
./gradlew build -x test
```

### Running the Application
```bash
# Run the application
./gradlew bootRun

# Run with specific profile
./gradlew bootRun --args='--spring.profiles.active=dev'
```

### Testing
```bash
# Run all tests
./gradlew test

# Run a specific test class
./gradlew test --tests com.example.demo.DemoApplicationTests

# Run tests with output
./gradlew test --info
```

### Development Tasks
```bash
# Clean build artifacts
./gradlew clean

# Check dependencies
./gradlew dependencies

# View project tasks
./gradlew tasks
```

## Project Structure

```
src/
├── main/
│   ├── java/com/example/demo/
│   │   ├── DemoApplication.java          # Main Spring Boot application entry point
│   │   └── user/                         # User domain module
│   │       ├── controller/               # REST controllers
│   │       ├── dto/                      # Data Transfer Objects with validation
│   │       ├── entity/                   # JPA entities
│   │       ├── repository/               # Spring Data JPA repositories (when created)
│   │       └── service/                  # Business logic services (when created)
│   └── resources/
│       ├── application.properties        # Application configuration (Oracle DB settings)
│       ├── templates/                    # Mustache templates for views
│       └── static/                       # Static resources (CSS, JS, images)
└── test/
    └── java/com/example/demo/
        └── DemoApplicationTests.java     # Test classes
```

## Architecture Notes

### Database Configuration
- **Primary**: Oracle database (ojdbc8 driver)
  - Connection: `jdbc:oracle:thin:@localhost:1521/ORCLPDB`
  - User: `app_user`
  - Hibernate DDL mode: `update` (auto-creates/updates tables)
- **Testing**: H2 in-memory database available as runtime dependency
- Spring Data JPA for data access layer with Oracle dialect

### Domain-Driven Package Structure
The project follows a domain-driven structure under `com.example.demo`:
- **user/** - User domain module containing:
  - **controller/** - REST API endpoints with `@RestController`
  - **dto/** - Request/response objects with Jakarta Validation annotations
  - **entity/** - JPA entities with proper `@Id` mapping
  - **repository/** - Spring Data JPA repositories (to be created)
  - **service/** - Business logic layer (to be created)

### View Layer
- Mustache templating engine configured
- Templates go in `src/main/resources/templates/`
- Static assets go in `src/main/resources/static/`

### Validation
- Jakarta Validation configured with `spring-boot-starter-validation`
- DTOs use annotations like `@NotBlank` for request validation
- Controllers use `@Valid` with `BindingResult` for error handling

## Development Notes

- Java 21 toolchain configured
- Lombok annotations used extensively (`@Getter`, `@Setter`, `@NoArgsConstructor`, `@AllArgsConstructor`, `@ToString`, `@Slf4j`)
- Ensure Lombok plugin is installed in your IDE
- Tests use JUnit 5 (JUnit Platform)
- When creating new entities, ensure proper JPA annotations (`@Entity`, `@Id`, `@GeneratedValue`)
- When creating repositories, extend `JpaRepository<Entity, IdType>`
