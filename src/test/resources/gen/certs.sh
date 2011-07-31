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

if [ $# -ne 1 ]
then
	echo "Usage: `basename $0` -n keyname"
	echo "Generate an X.509 certificate, a PEM encoded private key, and a PKCS8 encoded private key."
	echo ""
	echo "  -n KEYNAME               a name to identify the generate certificate and keys"
	
	exit 1;
fi

NAME=$1

openssl req -x509 \
            -nodes \
            -days 365 \
            -subj "/C=US/ST=Somestate/L=Anytown/CN=localhost" \
            -newkey rsa:1024 \
            -keyout $NAME.pem \
            -out $NAME.x509

openssl pkcs8 -topk8 \
              -in $NAME.pem \
              -out $NAME.pkcs8 \
              -nocrypt \
              -inform PEM \
              -outform DER