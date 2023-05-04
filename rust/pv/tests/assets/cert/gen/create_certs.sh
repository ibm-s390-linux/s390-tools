#!/bin/bash
if [ $# -eq 0 ]; then
	path="."
else
	path="$1"
fi

if test -f "${path}"/host.crt; then
	exit 0
fi

python -m venv "${path}"/gen_venv
source "${path}"/gen_venv/bin/activate
pip3 install -r "${path}"/requirements.txt
cd "${path}" || exit 2
python3 ./create_certs.py
deactivate
