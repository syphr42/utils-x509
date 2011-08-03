#!/bin/sh

#
# Copyright 2011 Gregory P. Moyer
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

if [ $# -lt 1 ]
then
	echo "Usage: `basename $0` keyname [host]"
	echo "Generate an X.509 certificate, a PEM encoded private key, and a PKCS8 encoded private key."
	echo ""
	echo "  KEYNAME                  a name to identify the generate certificate and keys"
	echo "  HOST                     the host name to be identified in the certificate (default: localhost)"
	
	exit 1;
fi

NAME=$1

if [ $# -gt 1 ]
then
	HOST=$2
else
	HOST=localhost
fi

openssl req -x509 \
            -nodes \
            -days 365 \
            -subj "/CN=$HOST" \
            -newkey rsa:1024 \
            -keyout $NAME.pem \
            -out $NAME.x509

openssl pkcs8 -topk8 \
              -in $NAME.pem \
              -out $NAME.pkcs8 \
              -nocrypt \
              -inform PEM \
              -outform DER