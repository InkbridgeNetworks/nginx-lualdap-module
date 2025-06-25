#!/bin/sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${BUILD_DIR:-$SCRIPT_DIR/build}"
NGINX_BIN="${NGINX_BIN:-$BUILD_DIR/nginx/sbin/nginx}"
NGINX_CONF="${NGINX_CONF:-$SCRIPT_DIR/ci/nginx/nginx.conf}"
LOG_DIR="${LOG_DIR:-$BUILD_DIR/test/log}"
RUN_DIR="${RUN_DIR:-$BUILD_DIR/test/run}"
PID_FILE="${PID_FILE:-$RUN_DIR/nginx.pid}"
VERBOSE=0
MULTI_THREAD="auto"
MODE="fg"

debug() {
    [ "$VERBOSE" -gt 0 ] && echo "$*" >&1
}

error() {
    echo "$*" >&2
}

usage() {
    cat <<EOF
Usage: $0 [-v] [-t <N>] <command> [mode]

Commands:
  start <fg|bg|fg-mt|bg-mt>   Start nginx in the specified mode
  stop                        Stop nginx gracefully
  reload                      Reload nginx configuration (HUP)
  status                      Show nginx running status

Modes:
  fg       Foreground mode, errors to stderr
  bg       Background mode, errors to \$LOG_DIR/error.log
  fg-mt    Foreground, multithreaded
  bg-mt    Background, multithreaded

Options:
  -v       Enable debug output
  -t <N>   Number of worker threads to use for fg-mt/bg-mt modes (default: auto)

Environment overrides:
  BUILD_DIR       Default: ./build
  NGINX_BIN       Default: \$BUILD_DIR/nginx/sbin/nginx
  NGINX_CONF      Default: ./ci/nginx/nginx.conf
  LOG_DIR         Default: \$BUILD_DIR/test/log
  RUN_DIR         Default: \$BUILD_DIR/test/run
  PID_FILE        Default: \$RUN_DIR/nginx.pid
EOF
    exit 1
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -v)
                VERBOSE=1
                shift
                ;;
            -t)
                shift
                if echo "$1" | grep -Eq '^(auto|[1-9][0-9]*)$'; then
                    MULTI_THREAD="$1"
                else
                    error "Invalid thread count: '$1' — must be 'auto' or a positive integer"
                    exit 1
                fi
                shift
                ;;
            -*)
                error "Unknown option: $1"
                usage
                ;;
            *)
                break
                ;;
        esac
    done

    ACTION="$1"
    [ -n "$2" ] && MODE="$2"
}

nginx_check_paths() {
    if [ ! -x "$NGINX_BIN" ]; then
        error "$NGINX_BIN not found or not executable"
        exit 1
    fi
    if [ ! -f "$NGINX_CONF" ]; then
        error "$NGINX_CONF not found"
        exit 1
    fi
}

nginx_prepare_dirs() {
    mkdir -p "$LOG_DIR" "$RUN_DIR"
}

nginx_start() {
    debug "Starting nginx in mode: $MODE with thread count: $MULTI_THREAD"

    case "$MODE" in
        fg)
            exec "$NGINX_BIN" -c "$NGINX_CONF" -e /dev/stderr -g "daemon off;"
            ;;
        bg)
            nginx_prepare_dirs
            "$NGINX_BIN" -c "$NGINX_CONF" -e "${LOG_DIR}/debug.log" \
	        -g "daemon on; pid $PID_FILE;"
            return
            ;;
        fg-mt)
            exec "$NGINX_BIN" -c "$NGINX_CONF" -e /dev/stderr \
                -g "daemon off; worker_processes $MULTI_THREAD;"
            ;;
        bg-mt)
            nginx_prepare_dirs
            "$NGINX_BIN" -c "$NGINX_CONF" -e "${LOG_DIR}/debug.log" \
                -g "daemon on; pid $PID_FILE; worker_processes $MULTI_THREAD;"
            return
            ;;
        *)
            error "Invalid mode: $MODE"
            usage
            ;;
    esac
}

nginx_stop() {
    debug "Stopping nginx"

    if [ ! -f "$PID_FILE" ]; then
        error "No PID file found at $PID_FILE"
        exit 1
    fi

    PID=$(cat "$PID_FILE")
    debug "Found PID: $PID"

    if ! kill -0 "$PID" 2>/dev/null; then
        error "No running process with PID $PID"
        rm -f "$PID_FILE"
        exit 1
    fi

    kill "$PID"
    debug "Sent TERM to nginx (PID $PID)"

    for _ in $(seq 1 25); do
        sleep 0.2
        if ! kill -0 "$PID" 2>/dev/null; then
            debug "nginx stopped cleanly"
            return
        fi
    done

    debug "nginx did not stop in time, sending KILL"
    kill -9 "$PID"
}

nginx_reload() {
    debug "Reloading nginx"

    if [ ! -f "$PID_FILE" ]; then
        error "No PID file found at $PID_FILE"
        exit 1
    fi

    PID=$(cat "$PID_FILE")
    debug "Found PID: $PID"

    if ! kill -0 "$PID" 2>/dev/null; then
        error "No running nginx to reload"
        rm -f "$PID_FILE"
        exit 1
    fi

    kill -HUP "$PID"
    debug "Sent HUP to nginx (PID $PID)"
}

nginx_status() {
    debug "Checking nginx status"

    if [ ! -f "$PID_FILE" ]; then
        echo "nginx not running (no PID file)"
        return 1
    fi

    PID=$(cat "$PID_FILE")
    debug "Found PID: $PID"

    if kill -0 "$PID" 2>/dev/null; then
        echo "nginx is running (PID $PID)"
        return 0
    fi

    echo "nginx not running, but PID file exists"
    return 1
}

main() {
    parse_args "$@"

    case "$ACTION" in
        start)
            nginx_check_paths
            nginx_start
            ;;
        stop)
            nginx_stop
            ;;
        reload)
            nginx_reload
            ;;
        status)
            nginx_status
            ;;
        *)
            usage
            ;;
    esac
}

main "$@"