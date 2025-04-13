FROM gcc:14 AS builder
WORKDIR /
COPY src/ src/
COPY makefile .
RUN make -j$(nproc)

FROM scratch
EXPOSE 8080 8443
COPY config.txt /
COPY resources/ resources/
COPY --from=builder /target/codeymccodeface /
CMD ["/codeymccodeface"]
