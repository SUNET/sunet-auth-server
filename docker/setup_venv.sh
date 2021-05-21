#!/bin/bash
#
# Run build commands that should never be docker-build cached
#

set -e
set -x

python3 -mvenv /opt/sunet/

cd /opt/sunet/sunet-auth-server/

PYPI="https://pypi.sunet.se/simple/"
/opt/sunet/bin/pip install -i ${PYPI} -U pip wheel
/opt/sunet/bin/pip install -i ${PYPI} -r requirements.txt

/opt/sunet/bin/pip freeze
