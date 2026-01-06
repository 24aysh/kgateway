ARG BASE_IMAGE

FROM $BASE_IMAGE

RUN apk -U upgrade

ARG GOARCH
COPY *sds-linux-$GOARCH /usr/local/bin/sds

USER 10101

ENTRYPOINT ["/usr/local/bin/sds"]
