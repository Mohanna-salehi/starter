FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o pan-vault ./cmd/pan-vault

RUN CGO_ENABLED=0 GOOS=linux go build -o migrate ./cmd/migrate


FROM alpine:latest AS app

WORKDIR /app

COPY --from=builder /app/pan-vault .

EXPOSE 8080

CMD ["./pan-vault"]



FROM alpine:latest AS migrate

WORKDIR /app


COPY --from=builder /app/migrate ./migrate
COPY --from=builder /app/db/migrations ./db/migrations

CMD ["./migrate"]