ARG BASE_IMAGE

FROM $BASE_IMAGE

RUN apk -U upgrade

ARG GOARCH
COPY *dummy-idp-linux-$GOARCH /usr/local/bin/dummy-idp

USER 10101

ENTRYPOINT ["/usr/local/bin/dummy-idp"]
