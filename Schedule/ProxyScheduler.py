# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     ProxyScheduler
   Description :
   Author :        JHao
   date：          2019/8/5
-------------------------------------------------
   Change Activity:
                   2019/8/5: ProxyScheduler
-------------------------------------------------
"""
__author__ = 'JHao'

import sys
from apscheduler.schedulers.blocking import BlockingScheduler

sys.path.append('../')

from Schedule import doRawProxyCheck, doUsefulProxyCheck
from Manager import ProxyManager
from Util import LogHandler, get_origin_ips


class DoFetchProxy(ProxyManager):
    """ fetch proxy"""

    def __init__(self):
        ProxyManager.__init__(self)
        self.log = LogHandler('fetch_proxy')

    def main(self):
        self.log.info("start fetch proxy")
        self.fetch()
        self.log.info("finish fetch proxy")


def rawProxyScheduler(origin_ips):
    DoFetchProxy().main()
    doRawProxyCheck(origin_ips)


def usefulProxyScheduler(origin_ips):
    doUsefulProxyCheck(origin_ips)


def runScheduler():
    origin_ips = get_origin_ips()
    rawProxyScheduler(origin_ips)
    usefulProxyScheduler(origin_ips)

    scheduler_log = LogHandler("scheduler_log")
    scheduler = BlockingScheduler(logger=scheduler_log)

    scheduler.add_job(rawProxyScheduler, 'interval', args=(origin_ips,), minutes=5, id="raw_proxy_check",
                      name="raw_proxy定时采集")
    scheduler.add_job(usefulProxyScheduler, 'interval', args=(origin_ips,), minutes=1, id="useful_proxy_check",
                      name="useful_proxy定时检查")

    scheduler.start()


if __name__ == '__main__':
    runScheduler()
