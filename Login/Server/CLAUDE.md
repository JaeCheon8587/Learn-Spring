# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Spring Boot 3.5.6 application built with Java 21 and Gradle. This is a login server demo project using:
- **Spring Data JPA** with H2 in-memory database
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
│   │   └── DemoApplication.java          # Main Spring Boot application entry point
│   └── resources/
│       ├── application.properties        # Application configuration
│       ├── templates/                    # Mustache templates for views
│       └── static/                       # Static resources (CSS, JS, images)
└── test/
    └── java/com/example/demo/
        └── DemoApplicationTests.java     # Test classes
```

## Architecture Notes

### Database Configuration
- H2 in-memory database (runtime dependency)
- Spring Data JPA for data access layer
- Database console available at `/h2-console` (when enabled in application.properties)

### View Layer
- Mustache templating engine configured
- Templates go in `src/main/resources/templates/`
- Static assets go in `src/main/resources/static/`

### Package Structure
- Base package: `com.example.demo`
- Main class: `DemoApplication` with `@SpringBootApplication`
- Following standard Spring Boot conventions

## Development Notes

- Java 21 toolchain configured
- Lombok annotations available (ensure IDE plugin installed)
- Tests use JUnit 5 (JUnit Platform)
- Follow Spring Boot best practices for package organization (controllers, services, repositories, entities)
