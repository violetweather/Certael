#!/usr/bin/env bash
set -euo pipefail

workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$workspace"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --release --locked -p certael-c-api
dotnet restore Certael.slnx
dotnet test Certael.slnx --no-restore -c Release --warnaserror
dotnet restore engines/unity/Runtime/Certael.Unity.csproj
dotnet build engines/unity/Runtime/Certael.Unity.csproj --no-restore -c Release --warnaserror

if [[ "$(uname -s)" == Darwin ]]; then
  clang -std=c17 -Wall -Wextra -Werror -Iruntime/certael-c-api/include \
    tests/native/c_abi_smoke.c target/release/libcertael_c_api.a \
    -framework Security -framework CoreFoundation -o /tmp/certael-abi
  clang++ -std=c++20 -Wall -Wextra -Werror -Iruntime/certael-c-api/include \
    tests/native/cpp_abi_smoke.cpp target/release/libcertael_c_api.a \
    -framework Security -framework CoreFoundation -o /tmp/certael-cpp
  /tmp/certael-abi
  /tmp/certael-cpp
elif [[ "$(uname -s)" == Linux ]]; then
  cc -std=c17 -Wall -Wextra -Werror -Iruntime/certael-c-api/include \
    tests/native/c_abi_smoke.c target/release/libcertael_c_api.a \
    -ldl -lpthread -lm -o /tmp/certael-abi
  c++ -std=c++20 -Wall -Wextra -Werror -Iruntime/certael-c-api/include \
    tests/native/cpp_abi_smoke.cpp target/release/libcertael_c_api.a \
    -ldl -lpthread -lm -o /tmp/certael-cpp
  /tmp/certael-abi
  /tmp/certael-cpp
fi
if command -v c++ >/dev/null; then
  c++ -std=c++20 -Wall -Wextra -Werror tests/native/godot_agent_codec_smoke.cpp \
    -o /tmp/certael-godot-agent-codec
  /tmp/certael-godot-agent-codec
fi

if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
  suffix="$$"
  postgres="certael-verify-pg-$suffix"
  redis="certael-verify-redis-$suffix"
  password=$(openssl rand -hex 24)
  cleanup() { docker rm -f "$postgres" "$redis" >/dev/null 2>&1 || true; }
  trap cleanup EXIT
  docker run -d --name "$postgres" -e POSTGRES_USER=certaeltest \
    -e POSTGRES_PASSWORD="$password" -e POSTGRES_DB=certaeltest \
    -p 127.0.0.1::5432 postgres:17-alpine >/dev/null
  docker run -d --name "$redis" -p 127.0.0.1::6379 redis:8-alpine \
    redis-server --appendonly yes >/dev/null
  postgres_port=$(docker port "$postgres" 5432/tcp | sed 's/.*://')
  redis_port=$(docker port "$redis" 6379/tcp | sed 's/.*://')
  for _ in {1..30}; do
    docker exec "$postgres" pg_isready -U certaeltest -d certaeltest >/dev/null 2>&1 \
      && break
    sleep 1
  done
  for _ in {1..30}; do
    docker exec "$redis" redis-cli ping 2>/dev/null | grep -q PONG && break
    sleep 1
  done
  CERTAEL_TEST_POSTGRES="Host=127.0.0.1;Port=$postgres_port;Database=certaeltest;Username=certaeltest;Password=$password" \
  CERTAEL_TEST_REDIS="127.0.0.1:$redis_port,abortConnect=false" \
    dotnet test tests/Certael.Server.Tests/Certael.Server.Tests.csproj --no-restore \
      -c Release --filter 'Category=Integration' --warnaserror
  cleanup
  trap - EXIT
else
  echo "Docker unavailable: skipped PostgreSQL/Redis integration tests." >&2
fi

echo "Certael Core local verification passed."
