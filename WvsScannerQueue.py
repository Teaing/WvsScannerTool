#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author:Tea
# date 2014/06/25
# The WVS Scanner Report Auxiliary Tool

import os
import sys
import time
import Queue
import smtplib
import threading
import subprocess
from xml.dom import minidom  # 解析XML模块
from email.mime.text import MIMEText  # 发送邮件模块

mailto_list = ['mailqq@qq.com']  # 收件人
mail_host = "smtp.126.com"
mail_user = "mail126"  # 发件帐号
mail_pass = "mail126123"  # 发件密码
mail_postfix = "126.com"


# 读取文件内容取出URL，并且去重
def read_url(filepath):
    tmpfileurl = []
    filecontent = open(filepath)
    for url in filecontent:
        if url.__len__() > 4:
            tmpfileurl.append(url.replace('\n', ''))
    filecontent.close()
    fileurl = {}.fromkeys(tmpfileurl).keys()
    return fileurl


# 调用扫描函数后判断结果
def call_wvsscan_result(url):
    Rcode = start_wvsscanner(url)
    check_result_load(Rcode)


# 扫描结果进行读取，并且发送邮件，这里还可以写简洁
def check_result_load(Rcode):
    (RRcode, Mtag, RRdir) = Rcode.split('|')
    MTitle = 'WvsScanner Report--' + Mtag
    RRdir += '\\export.xml'
    if int(RRcode) == 3:
        MResult = '\n'.join(laod_xml_report(RRdir))
        send_mail(mailto_list, MTitle, MResult)
    elif int(RRcode) == 2:
        MResult = '\n'.join(laod_xml_report(RRdir))
        send_mail(mailto_list, MTitle, MResult)
    elif int(RRcode) == 1:
        MResult = '\n'.join(laod_xml_report(RRdir))
        send_mail(mailto_list, MTitle, MResult)
    else:
        print 'Info'


# 调用软件进行扫描操作
def start_wvsscanner(url):
    wvs = 'D:\Software\Web Vulnerability Scanner 9.5\wvs_console.exe'  # 定义的WVS_CONSLEL路径
    Time = time.strftime('%Y-%m-%d', time.localtime(time.time()))
    savefolder = 'D:\\Log\\Wvs\\' + Time + '\\' + httpreplace(url)  # 定义扫描以后的LOG结果
    if os.path.lexists(savefolder) is False:
        os.makedirs(savefolder)
    wvscommand = wvs + ' /Scan ' + url + ' /Profile default /Save /SaveFolder ' + savefolder \
                 + ' /exportxml --UseAcuSensor=FALSE --ScanningMode=Heuristic'
    print wvscommand
    doscan = subprocess.call(wvscommand)
    retresult = str(doscan) + '|' + url + '|' + savefolder
    return retresult


# 替换掉URL的http://字符跟特殊字符，为的是创建日志保存目录没得非法字符
def httpreplace(httpstr):
    return httpstr.replace('https://', '').replace('http://', '').replace('/', '').replace(':', '-')


# 解析XML报告文件，提取漏洞标题
def laod_xml_report(xmlname):
    Result = []
    HeadInfo = []
    tmpResult = []
    ResultContact = {'red': 'High', 'orange': 'Medium', 'blue': 'Low', 'green': 'Info'}
    dom = minidom.parse(xmlname)
    count = dom.getElementsByTagName('ReportItem')
    HeadInfo.append(dom.getElementsByTagName("StartURL")[0])
    HeadInfo.append(dom.getElementsByTagName("StartTime")[0])
    HeadInfo.append(dom.getElementsByTagName("FinishTime")[0])
    HeadInfo.append(dom.getElementsByTagName("ScanTime")[0])
    for i in HeadInfo:
        for n in i.childNodes:
            Result.append(n.nodeValue)
    for i in xrange(len(count)):
        color = dom.getElementsByTagName('ReportItem')[i].getAttribute('color')
        ReportItem = dom.getElementsByTagName("ReportItem")[i]
        Name = ReportItem.getElementsByTagName("Name")[0]
        if color in ResultContact:
            colorResult = ResultContact[color] + '\t'
        else:
            colorResult = 'Other\t'
        for textNode in Name.childNodes:
            tmpResult.append(colorResult + textNode.nodeValue)
    Result2 = {}.fromkeys(tmpResult).keys()
    Result2 = sortresultlist(Result2)
    Result.append('Vulnerable Count:' + str(len(Result2)))
    for n in xrange(len(Result2)):
        Result.append(Result2[n])
    return Result


# 将扫描结果进行排序,这太渣了
def sortresultlist(List):
    Result = []
    for i in List:
        if i.startswith('High'):
            Result.append(i)
    for i in List:
        if i.startswith('Medium'):
            Result.append(i)
    for i in List:
        if i.startswith('Low'):
            Result.append(i)
    for i in List:
        if i.startswith('Info'):
            Result.append(i)
    for i in List:
        if i.startswith('Other'):
            Result.append(i)
    return Result


# 发送通知邮件
def send_mail(to_list, sub, content):
    me = "WvsScanner<" + mail_user + "@" + mail_postfix + ">"
    msg = MIMEText(content, _subtype='plain', _charset='utf-8')
    msg['Subject'] = sub
    msg['From'] = me
    msg['To'] = ";".join(to_list)
    try:
        server = smtplib.SMTP()
        server.connect(mail_host)
        server.login(mail_user, mail_pass)
        server.sendmail(me, to_list, msg.as_string())
        server.close()
        return True
    except Exception, e:
        catchwrite(str(e))
        return False


# 异常写入文件记录
def catchwrite(errcode):
    filestr = "mailerror.txt"
    errtime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
    errfile = open(filestr, 'a')
    errfile.write(errtime + '\t' + errcode + '\n')
    errfile.close()


class ScanManager(object):

    def __init__(self, work_num=100, thread_num=5, res_list=[]):
        self.work_queue = Queue.Queue()
        self.threads = []
        self.work_list = res_list
        print work_num
        self.__init_work_queue(work_num)
        self.__init_thread_pool(thread_num)

    def __init_thread_pool(self, thread_num):
        for i in xrange(thread_num):
            self.threads.append(ScanWork(self.work_queue))

    def __init_work_queue(self, jobs_num):
        for i in xrange(jobs_num):
            self.add_job(do_job, self.work_list[i])

    def add_job(self, func, *args):
        self.work_queue.put((func, list(args)))

    def wait_allcomplete(self):
        for item in self.threads:
            if item.isAlive():
                item.join()


class ScanWork(threading.Thread):

    def __init__(self, work_queue):
        threading.Thread.__init__(self)
        self.work_queue = work_queue
        self.start()

    def run(self):
        while True:
            try:
                do, args = self.work_queue.get(block=False)
                do(args)
                self.work_queue.task_done()
            except:
                break


# 将Url推进去开始扫描
def do_job(args):
    for i in args:
        call_wvsscan_result(i)


def main():
    if len(sys.argv) != 2:
        print "Usage: %s D:\\Url.txt" % sys.argv[0]
        print "WvsScanner Auxiliary Tool"
        return
    filestr = sys.argv[1]
    Result = read_url(filestr)
    thread_count = 6  # 这里不能超过10，Windows下最多打开10个wvs_consoe进行扫描
    start_time = time.time()
    do_count = len(Result)
    work_manager = ScanManager(do_count, thread_count, Result)
    work_manager.wait_allcomplete()
    end_time = time.time()
    print "Complete Time:%s" % (end_time - start_time)


if __name__ == '__main__':
    main()
