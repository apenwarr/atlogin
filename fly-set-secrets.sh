#!/bin/sh
set -e -x
fly secrets set ATLOGIN_CONFIG=$(base64 -w0 state/config.json) ATLOGIN_SIGNING_KEY=$(base64 -w0 state/signing-key.json)
