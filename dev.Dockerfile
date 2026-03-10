FROM golang:1.25-bookworm AS builder

COPY . /src
WORKDIR /src

RUN GOPROXY=https://goproxy.cn go install github.com/go-delve/delve/cmd/dlv@latest
RUN GOPROXY=https://goproxy.cn make dev-build

FROM debian:stable-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
		ca-certificates  \
        netbase \
        && rm -rf /var/lib/apt/lists/ \
        && apt-get autoremove -y && apt-get autoclean -y

COPY --from=builder /go/bin/dlv /usr/local/bin/dlv
COPY --from=builder /src/bin /app
COPY ./configs /app/configs

WORKDIR /app

EXPOSE 2345
EXPOSE 8000
EXPOSE 9000

CMD ["dlv","--listen=:2345","--headless=true", "--api-version=2","--accept-multiclient","exec","./iwut-auth-center","--", "-conf", "./configs/config.yaml"]