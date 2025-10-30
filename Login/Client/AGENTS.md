# Repository Guidelines

## Project Structure & Module Organization
- `src/main/java/com/example/demo`: Spring Boot entry point plus `controller`, `service`, and `repository` packages; keep controllers thin and delegate logic to services.
- `src/main/resources/templates`: One Mustache view per route; share reusable fragments under `templates/fragments` when layouts repeat.
- `src/main/resources/static`: Serve CSS, JS, and images directly from this folder.
- `src/main/resources/application.properties`: Centralize profile toggles, H2 settings, and mail or OAuth keys with environment overrides.
- `src/test/java` & `src/test/resources`: Mirror production packages and store fixtures or seeded SQL used by integration tests.

## Build, Test, and Development Commands
- `./gradlew bootRun`: Launch the app with hot reload; confirm controller wiring and templates while iterating locally.
- `./gradlew test`: Run the full JUnit 5 suite; ensure green runs before every push or pull request.
- `./gradlew build`: Compile sources, execute tests, and produce the runnable JAR in `build/libs`.
- `./gradlew clean`: Remove previous build outputs when switching branches or resetting environments.

## Coding Style & Naming Conventions
Target Java 21 via the Gradle toolchain. Use tabs for indentation and place braces on the same line as declarations. Name classes and components in PascalCase (for example, `LoginController`), methods and fields in camelCase, and constants in UPPER_SNAKE_CASE. Mustache templates use TitleCase filenames that mirror controller methods. Prefer constructor injection for Spring beans and funnel complex rules into services to keep controllers focused on request handling.

## Testing Guidelines
Author JUnit 5 tests alongside production code, suffixing classes with `Tests` and matching package paths. Use `@WebMvcTest` for controller slices, `@DataJpaTest` for repository logic, and reserve `@SpringBootTest` for scenarios requiring the full context. Seed H2 fixtures in `src/test/resources` and run `./gradlew test` before committing.

## Commit & Pull Request Guidelines
Follow Conventional Commit subjects (`feat:`, `fix:`, `test:`, etc.) with subjects under 60 characters. Reference issue IDs in commit bodies (for example, `Refs #12`) and document configuration changes. Pull requests should summarize the change set, list validation commands, and attach UI screenshots whenever templates or static assets change. Keep PRs narrow so reviewers can reproduce results with the commands above.

## Security & Configuration Tips
Store secrets in environment variables instead of source files and load them through Spring profiles. Disable the H2 console for deployed environments (`spring.h2.console.enabled=false`) and reset the in-memory database with `./gradlew clean` if schema drift is suspected. Review `application.properties` for sensitive defaults before shipping.
