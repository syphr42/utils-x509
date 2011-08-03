#!/usr/bin/perl -w

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

use Getopt::Std;
$Getopt::Std::STANDARD_HELP_VERSION = "true";

sub HELP_MESSAGE()
{
	printf("Usage: $0 -n keyname [-h host] [-t rsa|dsa] [-d directory]\n");
	printf("Generate an X.509 certificate, a PEM encoded private key, and a PKCS8 encoded private key.\n");
	printf("\n");
	printf("  -n KEYNAME               a name to identify the generate certificate and keys\n");
	printf("  -h HOST                  the host name to be identified in the certificate (default: localhost)\n");
	printf("  -t KEYTYPE               the algorithm to use when generating the certificate and keys (default: rsa)\n");
	printf("  -d DIRECTORY             the directory into which the certificate and keys will be generated (default: .)\n");
}

sub VERSION_MESSAGE()
{
	printf("$0 0.2\n");
	printf("Copyright 2011 Gregory P. Moyer\n");
	printf("\n");
	printf("Licensed under the Apache License, Version 2.0 (the \"License\");\n");
	printf("you may not use this file except in compliance with the License.\n");
	printf("You may obtain a copy of the License at\n");
	printf("\n");
	printf("    http://www.apache.org/licenses/LICENSE-2.0\n");
	printf("\n");
	printf("Unless required by applicable law or agreed to in writing, software\n");
	printf("distributed under the License is distributed on an \"AS IS\" BASIS,\n");
	printf("WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n");
	printf("See the License for the specific language governing permissions and\n");
	printf("limitations under the License.\n");
}

getopts('n:h:t:d:', \%cmdLine);
$name = $cmdLine{n};
$host = $cmdLine{h};
$type = $cmdLine{t};
$dir = $cmdLine{d};

if (!$name)
{
    printf("Key name not specified!\n\n");
    HELP_MESSAGE();
    exit(1);
}

if (!$host)
{
	$host = "localhost";
}

if (!$type)
{
	$type = "rsa";
}

if (!$dir)
{
	$dir = ".";
}

if ($type =~ m/rsa/i)
{
	$param = "1024";
}
elsif ($type =~ m/dsa/i)
{
	$param = "$dir/$name.dsaparam";
	system("openssl dsaparam -out \"$param\" 1024") == 0 or die("Failed to generate DSA parameters: $!\n");
}
else
{
	printf("Unknown key type: $type!\n\n");
    HELP_MESSAGE();
    exit(1);
}

system("openssl req -x509 -nodes -days 365 -subj \"/CN=$host\" -newkey $type:\"$param\" -keyout \"$dir/$name.pem\" -out \"$dir/$name.x509\"") == 0 or die("Failed to generate X.509 certificate: $!\n");
system("openssl pkcs8 -topk8 -in \"$dir/$name.pem\" -out \"$dir/$name.pkcs8\" -nocrypt -inform PEM -outform DER") == 0 or die("Failed to convert private key to PKCS8: $!\n");
