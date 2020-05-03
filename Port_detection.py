# -*- coding: UTF-8 -*-
import queue
import nmap
import datetime
import threading
import json
import os
import urllib3
import subprocess
import sys
import click

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

lock = threading.Lock()
final_domains = set()
insert = set()
ports = []
bad_ips = []


class PortScan(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self._queue = queue
    
    def run(self):
        while not self._queue.empty():
            scan_ip = self._queue.get()
            try:
                portscan(scan_ip)
            except Exception as e:
                print('run:', str(e))
                pass


# 调用masscan
def portscan(scan_ip):
    global count
    temp_ports = []  # 设定一个临时端口列表
    name = scan_ip + '.json'
    command = 'masscan.exe ' + scan_ip +' -p21,22,23,25,53,67,68,80,81,82,83,84,85,86,87,88,89,110,139,143,161,300,' \
        '389,443,445,465,512,513,514,591,593,832,837,873,888,901,981,993,1010,1080,1100,1241,1311,1352,1433,1434,' \
        '1521,1527,1582,1583,1723,1944,2049,2082,2082,2086,2087,2095,2096,2181,2222,2301,2375,2480,3000,3128,3306,' \
        '3333,3389,4000,4001,4002,4100,4125,4243,4443,4444,4567,4711,4712,4848,4849,4993,5000,5104,5108,5432,5555,' \
        '5632,5800,5801,5802,5900,5901,5984,5985,5986,6082,6225,6346,6347,6379,6443,6480,6543,6789,6984,7000,7001,' \
        '7002,7396,7474,7674,7675,7777,7778,8000,8001,8002,8003,8004,8005,8006,8008,8009,8010,8014,8042,8069,8075,' \
        '8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8093,8095,8016,8118,8123,8161,8172,8181,' \
        '8200,8222,8243,8280,8281,8333,8384,8403,8443,8500,8530,8531,8800,8806,8834,8880,8881,8887,8888,8910,8983,' \
        '8989,8990,8991,9000,9043,9060,9080,9090,9091,9200,9294,9295,9300,9443,9444,9800,9981,9988,9990,9999,10000,' \
        '10880,11211,11371,12043,12046,12443,15672,16225,16080,18091,18092,20000,20720,24465,27017,27018,28017,28080,' \
        '30821,43110,50070,61600 -oJ ' + name + ' --rate 100'
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    child.wait()  # 等待任务完成
    # 提取json文件中的端口
    if os.path.exists(name):
        with open(name, 'r') as f:
            for line in f:
                if line.startswith('{ '):
                    temp = json.loads(line[:-2])
                    temp1 = temp["ports"][0]
                    temp_ports.append(str(temp1["port"]))
    else:
        print('文件不存在')
        sys.exit()
    if len(temp_ports) > 30:
        count += 1
        print(scan_ip + ' 疑似存在waf')
        bad_ips.append(scan_ip)
        temp_ports.clear()  # 如果端口数量大于50，说明可能存在防火墙，属于误报，清空列表
    else:
        ports.append(temp_ports)  # 小于50则放到总端口列表里
        ips[scan_ip] = temp_ports
        if os.path.exists(name):
            os.remove(name)
            print('file detele')
        if ips.get(scan_ip):
            Scan(scan_ip)


# 调用nmap识别服务
def Scan(scan_ip):
    global count
    open_ports_list = ips[scan_ip]
    open_ports = ",".join(open_ports_list)
    nm = nmap.PortScanner()
    lock.acquire()
    click.secho(f'[*] 开始nmap扫描 ip: {scan_ip} => 端口: {open_ports}', fg='red')
    count += 1
    print('当前是第', count, '个目标')
    lock.release()
    try:
        ret = nm.scan(scan_ip, open_ports, arguments=nmap_arguments)
        try:
            output_item = ret['scan'][scan_ip]['tcp']
        except Exception:
            pass
        else:   # try语句无异常时执行else语句
            for port, port_info in output_item.items():  # 返回可遍历的(键, 值) 元组数组
                save_item = f"[+] {scan_ip} {port} {port_info['name']} {port_info['product']} {port_info['version']}"
                insert.add(scan_ip + '\t' + str(port) + '\t' + port_info['name'] + '\t' + port_info['product'] + ' '
                           + port_info['version'] + '\n')
                lock.acquire()
                print(save_item)
                lock.release()
            fw = open('ports3.txt', 'w+', encoding='utf-8')
            fw.writelines(insert)
            fw.close()
    except Exception as e:
        print(str(e))
        pass


def main():
    que = queue.Queue()
    try:
        # 要扫描的ip列表，一行一个
        f = open(r'ips.txt', 'r')
        for line in f.readlines():
            final_ip = line.strip()
            que.put(final_ip)
        f.close()
        threads = []
        thread_count = 6
        for i in range(thread_count):
            threads.append(PortScan(que))
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    except Exception as e:
        print('Main:', e)
        pass
    spend_time = (datetime.datetime.now() - start_time).seconds
    print("疑似存在waf的IP：")
    print(bad_ips)
    print('程序共运行了： ' + str(spend_time) + '秒')


if __name__ == '__main__':
    ips = {}
    index = 1
    count = 0
    start_time = datetime.datetime.now()
    path = r"D:\Security-Tools\masscan1.0.4\x64"    # masscan所在路径，可自行修改
    os.chdir(path)
    nmap_arguments = "-sV -Pn"
    main()
