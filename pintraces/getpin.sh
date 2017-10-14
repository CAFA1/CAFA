#!/usr/bin/env sh

# $Id: getpin.sh 6733 2012-09-26 14:22:44Z edmcman $
# Download and extract Pin

set -x

# check if pin dir exists first

wget 'http://software.intel.com/sites/landingpage/pintool/downloads/pin-2.11-49306-gcc.3.4.6-ia32_intel64-linux.tar.gz' -U "Mozilla/5.0 (compatible; MSIE 10.6; Windows NT 6.1; Trident/5.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727) 3gpp-gba UNTRUSTED/1.0" -O - | tar -xvz -C ..
rm -rf ../pin
mv ../pin-* ../pin
#make
