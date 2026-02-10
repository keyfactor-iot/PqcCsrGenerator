# Stage 1: Build with JDK 24
FROM eclipse-temurin:24-jdk AS build
WORKDIR /app

# Install Maven
RUN apt-get update && apt-get install -y maven git

# Clone and Build
RUN git clone https://github.com/keyfactor-iot/PqcCsrGenerator.git .
RUN mvn clean package -DskipTests

# Stage 2: Final Runtime Image (Java 24 JRE)
FROM eclipse-temurin:24-jre
WORKDIR /app

# Copy the built fat jar file
COPY --from=build /app/target/*-jar-with-dependencies.jar app.jar

# Create the directory and grant global write access
# so the non-root user can write to the mount point
RUN mkdir /output && chmod 777 /output

# Flexible Entrypoint
ENTRYPOINT ["java", "-jar", "app.jar"]