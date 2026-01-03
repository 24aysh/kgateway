ARG BASE_IMAGE

FROM $BASE_IMAGE

ARG TARGETPLATFORM

RUN apk -U upgrade

COPY $TARGETPLATFORM/sds-linux-* /usr/local/bin/sds

USER 10101

ENTRYPOINT ["/usr/local/bin/sds"]
