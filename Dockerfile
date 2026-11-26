FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/api ./cmd/api \
 && CGO_ENABLED=0 go build -o /out/connector ./cmd/connector \
 && CGO_ENABLED=0 go build -o /out/agent ./cmd/agent \
 && CGO_ENABLED=0 go build -o /out/treeward ./cmd/treeward

FROM alpine:3.20
RUN apk add --no-cache ca-certificates \
 && addgroup -g 10001 -S treeward \
 && adduser -u 10001 -S -G treeward -H -D treeward
WORKDIR /app
COPY --from=build /out/api /out/connector /out/agent /out/treeward /app/
USER 10001:10001
# default; overridden by k8s command
CMD ["/app/api"]
