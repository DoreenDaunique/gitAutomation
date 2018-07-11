#!/usr/bin/env bash
curl \
   -D- \
   -u charlie:charlie \
   -X POST \
   --data {see below} \
   -H "Content-Type: application/json" \
   http://localhost:8080/rest/api/2/issue/