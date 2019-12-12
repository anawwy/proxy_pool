# -*- coding: utf-8 -*-
# !/usr/bin/env python
"""
-------------------------------------------------
   File Name：     utilFunction.py
   Description :  tool function
   Author :       JHao
   date：          2016/11/25
-------------------------------------------------
   Change Activity:
                   2016/11/25: 添加robustCrawl、verifyProxy、getHtmlTree
-------------------------------------------------
"""

import requests
from lxml import etree

from Util.WebRequest import WebRequest


def robustCrawl(func):
    def decorate(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            pass
            # logger.info(u"sorry, 抓取出错。错误原因:")
            # logger.info(e)

    return decorate


def verifyProxyFormat(proxy):
    """
    检查代理格式
    :param proxy:
    :return:
    """
    import re
    verify_regex = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}"
    _proxy = re.findall(verify_regex, proxy)
    return True if len(_proxy) == 1 and _proxy[0] == proxy else False


def getHtmlTree(url, **kwargs):
    """
    获取html树
    :param url:
    :param kwargs:
    :return:
    """

    header = {'Connection': 'keep-alive',
              'Cache-Control': 'max-age=0',
              'Upgrade-Insecure-Requests': '1',
              'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko)',
              'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
              'Accept-Encoding': 'gzip, deflate, sdch',
              'Accept-Language': 'zh-CN,zh;q=0.8',
              }
    # TODO 取代理服务器用代理服务器访问
    wr = WebRequest()
    html = wr.get(url=url, header=header).content
    return etree.HTML(html)


def tcpConnect(proxy):
    """
    TCP 三次握手
    :param proxy:
    :return:
    """
    from socket import socket, AF_INET, SOCK_STREAM
    s = socket(AF_INET, SOCK_STREAM)
    ip, port = proxy.split(':')
    result = s.connect_ex((ip, int(port)))
    return True if result == 0 else False


def validUsefulProxy(proxy):
    """
    检验代理是否可用
    :param proxy:
    :return:
    """
    if isinstance(proxy, bytes):
        proxy = proxy.decode("utf8")
    proxies = {"http": "http://{proxy}".format(proxy=proxy)}
    try:
        r = requests.get('http://www.baidu.com', proxies=proxies, timeout=10, verify=False)
        if r.status_code == 200:
            return True
    except Exception as e:
        pass
    return False


def validUsefulProxyUnicom(proxy, origin_ips):
    """
    检验代理是否可用
    :param proxy:
    :return:
    """
    if isinstance(proxy, bytes):
        proxy = proxy.decode("utf8")
    proxies = {"http": "http://{proxy}".format(proxy=proxy)}
    is_ok = get_anonymity(proxies, origin_ips)
    if not is_ok:
        return False
    try:
        r = requests.get('https://vip.17wo.cn', headers={
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36',
        }, proxies=proxies, timeout=10, verify=False)
        if r.status_code == 200:
            return True
    except Exception as e:
        pass
    return False


def get_origin_ips():
    resp = requests.get('http://httpbin.org/get?show_env=1', timeout=10, verify=False)
    if resp.status_code == 200:
        data = resp.json()
        origin_ip_str = data.get('origin')
        if origin_ip_str:
            return [ip.strip() for ip in origin_ip_str.split(',') if ip]
    raise RuntimeError


def get_anonymity(proxies, origin_ips):
    try:
        r = requests.get('http://httpbin.org/get?show_env=1', proxies=proxies, timeout=10, verify=False)
        if r.status_code == 200:
            data = r.json()

            origin = data.get('origin')
            if origin:
                origin = {ip.strip() for ip in origin.split(',') if ip}
            headers = data.get('headers')
            x_forwarded_for = headers.get('X-Forwarded-For', None)
            x_real_ip = headers.get('X-Real-Ip', None)
            via = headers.get('Via', None)

            if (origin - origin_ips) != origin:
                anonymity = 3
            elif via is not None:
                anonymity = 2
            elif x_forwarded_for is not None and x_real_ip is not None:
                anonymity = 1
                return True
            else:
                anonymity = 0
    except Exception as e:
        pass
    return False
