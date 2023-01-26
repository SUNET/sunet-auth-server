#!/bin/bash

set -e
set -x

if [[ ! $app_name ]]; then
    echo "$0: Environment variable app_name not set (should be e.g. 'idp')"
    exit 1
fi

if [[ ! $app_entrypoint ]]; then
    echo "$0: Environment variable app_entrypoint not set (should be e.g. 'eduid.scimapi.run:api')"
    exit 1
fi

. /opt/sunet/bin/activate

# These could be set from Puppet if multiple instances are deployed
base_dir=${base_dir-'/opt/sunet'}
project_dir=${project_dir-"${base_dir}/sunet-auth-server/src"}
app_dir=${app_dir-"${project_dir}/${app_name}"}
cfg_dir=${cfg_dir-"${base_dir}/etc"}
username=${username-'sunet'}
group=${group-'sunet'}
# These *can* be set from Puppet, but are less expected to...
log_dir=${log_dir-'/var/log/sunet'}
state_dir=${state_dir-"${base_dir}/run"}
workers=${workers-1}
worker_class=${worker_class-uvicorn.workers.UvicornWorker}
worker_threads=${worker_threads-4}
worker_timeout=${worker_timeout-30}
# Need to tell Gunicorn to trust the X-Forwarded-* headers
forwarded_allow_ips=${forwarded_allow_ips-'*'}

test -d "${log_dir}" && chown -R ${username}:${group} "${log_dir}"
test -d "${state_dir}" && chown -R ${username}:${group} "${state_dir}"

# set PYTHONPATH if it is not already set using Docker environment
export PYTHONPATH=${PYTHONPATH-${project_dir}}
echo "PYTHONPATH=${PYTHONPATH}"

# nice to have in docker run output, to check what
# version of something is actually running.
/opt/sunet/bin/pip freeze
test -f /revision.txt && cat /revision.txt; true

extra_args=""
if [ -f "/opt/sunet/DEVEL_MODE" ]; then
    # developer mode, restart on code changes
    extra_args="${extra_args:+${extra_args} }--reload"
    # load mounted sources
    export PYTHONPATH="${PYTHONPATH:+${PYTHONPATH}:}/opt/sunet/src"
fi

echo ""
echo "$0: Starting ${app_name}"

exec start-stop-daemon --start -c ${username}:${group} --exec \
     /opt/sunet/bin/gunicorn \
     --pidfile "${state_dir}/${app_name}.pid" \
     --user=${username} --group=${group} -- \
     --bind 0.0.0.0:8080 \
     --workers "${workers}" --worker-class "${worker_class}" \
     --threads "${worker_threads}" --timeout "${worker_timeout}" \
     --forwarded-allow-ips="${forwarded_allow_ips}" \
     --access-logfile "${log_dir}/${app_name}-access.log" \
     --error-logfile "${log_dir}/${app_name}-error.log" \
     --capture-output \
     ${extra_args} "${app_entrypoint}"
