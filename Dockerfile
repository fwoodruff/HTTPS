FROM gcc:14 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    liburing-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /
COPY src/ src/
COPY makefile .
RUN make STATIC=1 -j$(nproc)

FROM scratch
EXPOSE 8080 8443
COPY config.txt /etc/codeymccodeface/
COPY resources/ /etc/codeymccodeface/resources/
COPY --from=builder /target/codeymccodeface /
CMD ["/codeymccodeface"]
