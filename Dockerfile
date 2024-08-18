FROM gcc:13 as builder
WORKDIR /
COPY src/ src/
COPY makefile .
RUN make -j$(nproc)

FROM scratch
EXPOSE 80 443
COPY config.txt /
COPY resources/ resources/
COPY --from=builder /target/codeymccodeface /
CMD ["/codeymccodeface"]
