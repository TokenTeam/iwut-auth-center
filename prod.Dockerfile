FROM golang:1.25-bookworm AS builder

COPY . /src
WORKDIR /src

RUN GOPROXY=https://goproxy.cn CGO_ENABLED=0 make build

FROM gcr.io/distroless/static-debian12

COPY --from=builder /src/bin /app
COPY ./configs /app/configs

WORKDIR /app

EXPOSE 8000
EXPOSE 9000

CMD ["./iwut-auth-center", "-conf", "./configs/config.yaml"]