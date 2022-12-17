#!/bin/bash
nc smtpd 25 | sed -u 's/220.*smtp4dev ready/220 smtp.gmail.com ESMTP 72-20020a62184b000000b0056bb0357f5bsm9949587pfy.192 - gsmtp/g'
