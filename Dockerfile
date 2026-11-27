FROM --platform=$BUILDPLATFORM gsoci.azurecr.io/giantswarm/alpine:3.24.4 AS certs
RUN apk add --no-cache ca-certificates

FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ARG TARGETOS
ARG TARGETARCH
COPY credential-api-${TARGETOS}-${TARGETARCH} /credential-api
USER 65532:65532
ENTRYPOINT ["/credential-api"]
