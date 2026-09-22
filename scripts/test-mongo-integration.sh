#!/usr/bin/env bash
set -euo pipefail

container_name="iwut-auth-center-mongo-integration-$$"
mongo_port="${MONGODB_INTEGRATION_PORT:-27029}"
if ! [[ "${mongo_port}" =~ ^[0-9]+$ ]] || (( mongo_port < 1 || mongo_port > 65535 )); then
  echo "MONGODB_INTEGRATION_PORT must be between 1 and 65535" >&2
  exit 1
fi

cleanup() {
  docker rm -f "${container_name}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run --detach --rm \
  --name "${container_name}" \
  --ulimit nofile=65536:65536 \
  --publish "127.0.0.1:${mongo_port}:${mongo_port}" \
  mongo:8.2.12 \
  mongod --bind_ip_all --port "${mongo_port}" --replSet auth-test >/dev/null

ready=false
for _ in $(seq 1 60); do
  if docker exec "${container_name}" mongosh --quiet --port "${mongo_port}" --eval 'db.runCommand({ping: 1}).ok' >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
if [ "${ready}" != true ]; then
  echo "MongoDB did not become ready" >&2
  exit 1
fi

docker exec "${container_name}" mongosh --quiet --port "${mongo_port}" --eval \
  "rs.initiate({_id:'auth-test',members:[{_id:0,host:'127.0.0.1:${mongo_port}'}]})" >/dev/null

ready=false
for _ in $(seq 1 60); do
  if docker exec "${container_name}" mongosh --quiet --port "${mongo_port}" \
    --eval 'if (!db.hello().isWritablePrimary) { quit(1) }' >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
if [ "${ready}" != true ]; then
  echo "MongoDB replica set did not elect a primary" >&2
  exit 1
fi

export MONGODB_INTEGRATION_URI="mongodb://127.0.0.1:${mongo_port}/?replicaSet=auth-test&directConnection=true"

go test -count=1 "$@" ./...
