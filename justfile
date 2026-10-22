# justfile for evomi-proxy-bridge (https://just.systems)
# Run `just` with no args to list recipes.

py := "python3"

# list recipes
default:
    @just --list

# run the bridge (reads .env automatically)
run *args:
    {{ py }} main.py {{ args }}

# offline unit tests
test:
    {{ py }} -m unittest discover -s tests -v

# compile check + offline tests
check:
    {{ py }} -m py_compile config.py main.py proxy_server.py
    {{ py }} -m unittest discover -s tests

# live test against real Evomi creds (requires EVOMI_USER/EVOMI_PASS in env)
live-test:
    EVOMI_LIVE_TEST=1 {{ py }} -m unittest tests.test_live -v

# remove bytecode caches
clean:
    rm -rf __pycache__ tests/__pycache__
