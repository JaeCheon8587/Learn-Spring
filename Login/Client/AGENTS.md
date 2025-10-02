# Repository Guidelines

## Project Structure & Module Organization
- `src/main/java/com/example/demo`: Spring Boot entry point and HTTP controllers; add new packages such as `service` or `repository` under this namespace.
- `src/main/resources/templates`: Mustache views (e.g., `Login.mustache`). Keep templates single-responsibility and pair each controller route with a template here.
- `src/main/resources/static`: Place CSS, JS, and image assets served directly by Spring Boot.
- `src/main/resources/application.properties`: Centralize environment configuration, including H2 settings and profile overrides.
- `src/test/java`: JUnit tests mirroring the main package structure.
- `build/`: Generated artifacts that should remain untouched.

## Build, Test & Development Commands
- `./gradlew bootRun` – launches the Spring Boot app with the embedded server for local development.
- `./gradlew test` – runs the JUnit 5 suite; ensure it passes before submitting changes.
- `./gradlew build` – compiles, runs tests, and produces the executable jar in `build/libs`.
- `./gradlew clean` – removes compiled output; run before reproducing build issues.

## Coding Style & Naming Conventions
- Target Java 21 and rely on the Gradle toolchain to enforce versioning.
- Preserve the existing tab-based indentation and place braces on the same line as declarations.
- Name classes and Spring components with PascalCase (for example, `LoginController`), methods and fields in camelCase, and Mustache templates with TitleCase file names.
- Favor constructor injection for Spring beans and keep controllers thin, delegating logic to service classes.

## Testing Guidelines
- Write JUnit 5 tests under `src/test/java`, following the same package as the code under test and suffixing classes with `Tests`.
- Prefer `@WebMvcTest` for controller slices and `@SpringBootTest` only when full context loading is required.
- Add mocked H2 data or test fixtures in `src/test/resources` when integration coverage is needed.
- Run `./gradlew test` before every push and ensure new features include assertions that guard regressions.

## Commit & Pull Request Guidelines
- Follow Conventional Commits (`feat:`, `fix:`, `test:`, etc.) with concise subject lines under 60 characters and optional bullet points in the body.
- Reference issue IDs in the body (for example, `Refs #12`) and describe any configuration changes.
- PRs should summarize the change, list manual or automated tests run, and include UI screenshots when templates or static assets change.
- Keep PRs focused; split unrelated changes into separate branches and ensure reviewers can reproduce results with the commands above.
