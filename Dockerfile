FROM gcc:14 AS builder
WORKDIR /
COPY src/ src/
COPY bench/ bench/
COPY main.cpp .
COPY makefile .
RUN make STATIC=1 -j$(nproc) && make STATIC=1 bench

FROM scratch
EXPOSE 8080 8443
COPY config.txt /etc/codeymccodeface/
COPY resources/ /etc/codeymccodeface/resources/
COPY --from=builder /target/codeymccodeface /
CMD ["/codeymccodeface"]
