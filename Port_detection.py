# -*- coding: UTF-8 -*-
import queue
import nmap
import datetime
import threading
import requests
import re
import json
import os
import sys
import urllib3
import argparse
from selenium import webdriver
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


final_domains = []
ports = []


class PortScan(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self._queue = queue

    def run(self):
        while not self._queue.empty():
            scan_ip = self._queue.get()
            try:
                portscan(scan_ip)
                Scan(scan_ip)
            except Exception as e:
                print('run:', str(e))
                pass

# 调用masscan


def portscan(scan_ip):
    temp_ports = []  # 设定一个临时端口列表
    os.system(
        'masscan.exe ' +
        scan_ip +
        ' -p1-65535 -oJ masscan.json --rate 2000')
    # 提取json文件中的端口
    with open('masscan.json', 'r') as f:
        for line in f:
            if line.startswith('{ '):
                temp = json.loads(line[:-2])
                temp1 = temp["ports"][0]
                temp_ports.append(str(temp1["port"]))
    if len(temp_ports) > 50:
        temp_ports.clear()  # 如果端口数量大于50，说明可能存在防火墙，属于误报，清空列表
    else:
        ports.extend(temp_ports)  # 小于50则放到总端口列表里


# 获取网站的web应用程序名和网站标题信息
def Title(scan_url_port, service_name):
    try:
        r = requests.get(scan_url_port, timeout=10, verify=False)
        if len(r.apparent_encoding):
            r.encoding = r.apparent_encoding
        server = ''
        language = ''
        headers = str(r.headers)
        if headers.find('Server') + 1:
            server = r.headers['Server']
        if headers.find('X-Powered-By') + 1:
            language = r.headers['X-Powered-By']
        title = re.findall(r'(?<=\<title\>)(?:.|\n)+?(?=\<)', r.text, re.S)
        title = str(title).strip('[]').strip('\'')
        if not title:
            title = re.search('>.+</title>', r.text)
            if title:
                title = title.group()
                title = title.strip('>').strip('</title')
        if not title:
            title = get_title(scan_url_port)
            final_domains.append(
                scan_url_port +
                '    ' +
                service_name +
                '    ' +
                language +
                '    ' +
                server +
                '    ' +
                title)
        else:
            final_domains.append(
                scan_url_port +
                '    ' +
                service_name +
                '    ' +
                language +
                '    ' +
                server +
                '    ' +
                title)
    except Exception as e:
        print('Title:', str(e))
        pass

# 调用nmap识别服务


def Scan(scan_ip):
    nm = nmap.PortScanner()
    try:
        for port in ports:
            ret = nm.scan(scan_ip, port, arguments='-Pn,-sS')
            service_name = ret['scan'][scan_ip]['tcp'][int(port)]['name']
            print(
                '[*]主机 ' +
                scan_ip +
                ' 的 ' +
                str(port) +
                ' 端口服务为：' +
                service_name)
            if service_name in ['https']:
                scan_url_port = 'https://' + scan_ip + ':' + str(port)
                Title(scan_url_port, service_name)
            elif service_name in ['http']:
                scan_url_port = 'http://' + scan_ip + ':' + str(port)
                Title(scan_url_port, service_name)
            else:
                final_domains.append(
                    scan_ip + ':' + str(port) + '    ' + service_name)
    except Exception as e:
        print('Scan:', str(e))
        pass


def get_title(test_url):
    chrome_options = webdriver.ChromeOptions()
    # 使用headless无界面浏览器模式
    chrome_options.add_argument('--headless')  # 增加无界面选项
    chrome_options.add_argument('--disable-gpu')  # 如果不加这个选项，有时定位会出现问题
    browser = webdriver.Chrome(options=chrome_options)
    browser.get(test_url)
    title = browser.title
    browser.quit()
    return title


def parser_args():
    parser = argparse.ArgumentParser(usage='python Port_detection.py --target [urls file]')
    parser.add_argument('-t', '--target', dest='target', help='The destination of file path', required=True)
    if len(sys.argv) == 1:
        sys.argv.append('-h')
    args = parser.parse_args()
    return args


def main():
    que = queue.Queue()
    try:
        f = open(url_path, 'r')
        for line in f.readlines():
            final_ip = line.strip()
            que.put(final_ip)
        threads = []
        thread_count = 30
        for i in range(thread_count):
            threads.append(PortScan(que))
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        f.close()
    except Exception as e:
        print('Main:', e)
        pass


if __name__ == '__main__':
    start_time = datetime.datetime.now()
    argv = parser_args()
    url_path = argv.target
    path = r"D:\Security Tools\masscan1.0.4\x64"              #注意更改路径
    os.chdir(path)
    main()
    for url in final_domains:
        with open(r'scan_url_port.txt', 'a') as ff:
            ff.write(url + '\n')
    spend_time = (datetime.datetime.now() - start_time).seconds
    print('程序共运行了： ' + str(spend_time) + '秒')
