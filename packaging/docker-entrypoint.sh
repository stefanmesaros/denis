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
#   docker run ... denis agent        -- a remote agent that reports to a master (settings from DENIS_MASTER,
#                                         DENIS_AGENT_TOKEN, DENIS_AGENT_ID, ... or flags after "agent"). Same
#                                         capture needs as "run"; keeps its database in /data/agent.db.
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
  agent)
    shift
    # compose cannot require these only for the agent service (it interpolates every service), so check here
    for v in DENIS_MASTER DENIS_AGENT_TOKEN DENIS_AGENT_ID; do
      eval "val=\${$v:-}"
      [ -n "$val" ] || { echo "set $v (Sites, Add agent in the console shows the values)" >&2; exit 2; }
    done
    exec denis agent --db "${DENIS_AGENT_DB:-/data/agent.db}" "$@"
    ;;
  "")
    exec denis run --db "$DB"
    ;;
  *)
    exec denis "$@"
    ;;
esac
