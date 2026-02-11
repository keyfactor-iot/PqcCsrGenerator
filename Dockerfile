FROM eclipse-temurin:24-jdk AS build
WORKDIR /app
RUN apt-get update && apt-get install -y maven git
RUN git clone https://github.com/keyfactor-iot/PqcCsrGenerator.git .
RUN mvn clean package -DskipTests

FROM eclipse-temurin:24-jre
WORKDIR /app
COPY --from=build /app/target/PqcCsrGenerator.jar app.jar
RUN chmod 644 app.jar
RUN mkdir /output && chmod 777 /output

# Using the exec form ["/bin/sh", "-c", ...] allows us to pass arguments to the shell
ENTRYPOINT ["/bin/sh", "-c", "java ${JAVA_OPTS} -jar app.jar \"$@\"", "--"]