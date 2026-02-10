FROM eclipse-temurin:24-jdk AS build
WORKDIR /app
RUN apt-get update && apt-get install -y maven git
RUN git clone https://github.com/keyfactor-iot/PqcCsrGenerator.git .
RUN mvn clean package -DskipTests

FROM eclipse-temurin:24-jre
WORKDIR /app
COPY --from=build /app/target/PqcCsrGenerator.jar app.jar

# Create a wrapper script to fix the Java argument order
RUN echo '#!/bin/sh\nprops=""\nargs=""\nfor arg in "$@"; do\n  case $arg in\n    -D*) props="$props $arg" ;;\n    *) args="$args $arg" ;;\n  esac\ndone\nexec java $props -jar app.jar $args' > /entrypoint.sh && chmod +x /entrypoint.sh

RUN mkdir /output && chmod 777 /output
ENTRYPOINT ["/entrypoint.sh"]