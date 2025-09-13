# Spring Boot Login & Registration

A clean, generic login/registration system built with:
- **Backend Framework**: Spring Boot 3 (REST APIs, Dependency Injection)
- **Build Tool**: Maven
- **Database**: MySQL with Hibernate/JPA ORM
- **Authentication**:
  - Spring Security (JWT-Based Authentication & Authorization)
  - Google OAuth 2.0 (via Spring Security OAuth2 Client)
- **Persistence Layer**: JPA Repositories with transactional services
- **Other**:
  - Custom OAuth2 Success Handler (Google Login Auto-Registration)
  - Password Hashing with BCrypt

## Setup
1. Clone repo
2. Copy `src/main/resources/application.properties.example` to `application.properties`
3. Set your environment variables for DB credentials
4. Run in bash/terminal: mvn spring-boot:run
