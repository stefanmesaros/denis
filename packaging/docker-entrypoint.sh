#!/bin/sh
# Two paths through the same image (see Dockerfile/docker-compose.yml/docs/docker.md):
#
#   docker run ... denis demo         -- evaluation: loads the built-in demo data on first start
#                                         (skipped if $DENIS_DB already exists -- restarting the
#                                         container never re-loads or wipes it), then serves it.
#                                         No capture, so no special network mode or capabilities
#                                         are needed; this is the bridge-networked "demo" service
#                                         in docker-compose.yml.
#   docker run ... denis run [flags]  -- a real collector (the default: plain `denis run` if no
#                                         argument is given at all). Needs host networking and
#                                         NET_RAW/NET_ADMIN to actually capture anything -- see the
#                                         "capture" service in docker-compose.yml. Passes through
#                                         whatever flags follow (--iface, --flows, --profile ot...).
#
# Anything else (denis --version, denis user reset ..., denis backup ...) is run as given: this is
# an entrypoint, not a restriction on what the image can do.
set -e

DB="${DENIS_DB:-/data/denis.db}"

case "$1" in
  demo)
    shift
    if [ ! -f "$DB" ]; then
      echo "docker-entrypoint: no database at $DB yet -- loading the built-in demo data"
      denis demo --db "$DB" load
    fi
    exec denis serve --db "$DB" "$@"
    ;;
  run)
    shift
    exec denis run --db "$DB" "$@"
    ;;
  "")
    exec denis run --db "$DB"
    ;;
  *)
    exec denis "$@"
    ;;
esac
