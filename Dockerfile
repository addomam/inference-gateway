# Native release build for the builder's architecture.
# CI builds linux/amd64 and does not push the image.
# An arm64 image is the same Dockerfile on an arm64 builder, or
# `docker buildx build --platform linux/arm64`; that path is not run in CI.
FROM rust:1.99.1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build --chown=65532:65532 /src/target/release/infer /infer
USER 65532:65532
EXPOSE 8080 8081
ENTRYPOINT ["/infer"]
CMD ["--config", "/etc/infer/infer.toml", "serve"]
