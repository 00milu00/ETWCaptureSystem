import base64
import datetime
import hashlib
import json
import os
import queue
import socket
import subprocess
import threading
import time
import uuid
import psutil
import pywintypes
import win32security


def getIPHexStr(clientip):
    ipNums = [int(num) for num in clientip.split('.')]
    ipHexNums = []
    for num in ipNums:
        if len(hex(num)[2:]) < 2:
            ipHexNums.append('0' + hex(num)[2:])
        else:
            ipHexNums.append(hex(num)[2:])
    return "".join(ipHexNums)


class kernelMonitorClient:
    # 过滤的进程号
    clientPid = 0
    wtracePid = 0
    # 数据库服务器的ip地址与端口
    host = "192.168.16.130"
    serverPort = 12345
    chServerPort = 0
    # 本客户端对应的令牌
    token = ""
    # 命令行参数
    params = []
    wtracePath = "./wtrace.exe"
    summaryParam = "--nosummary"
    isApplyNoSummary = True
    filtersParams = [

    ]
    isApplyFilter = False
    handlersParam = "process,tcp,udp,file"
    isApplyHandlers = True
    # 停止信号
    stop = False
    finishMonitor = False
    finishParse = False
    # 缓冲区大小
    buffSize = 4096
    # 事件词典
    eventDict = {
        'FileIO': {
            'Write': 'write',
            'Create': '',
            'FSControl': '',
            'Read': 'read',
            'DirEnum': '',
            'Cleanup': '',
            'Close': '',
            'SetInfo': '',
            'QueryInfo': '',
            'Delete': 'delete',
            'Flush': '',
            'Rename': 'rename'
        }, 'UdpIp': {
            'Send': 'send',
            'Recv': 'recv',
            'RecvIPV6': 'recv',
            'SendIPV6': 'send'
        }, 'Thread': {
            'Stop': 'end',
            'Start': 'start'
        }, 'TcpIp': {
            'Recv': 'recv',
            'TCPCopy': 'copy',
            'Send': 'send',
            'Connect': 'start',
            'Reconnect': 'start',
            'Disconnect': 'end',
            'SendIPV6': 'send',
            'RecvIPV6': 'recv',
            'Accept': 'start',
            'DisconnectIPV6': 'end',
            'ConnectIPV6': 'start',
            'ReconnectIPV6': 'start',
            'TCPCopyIPV6': 'copy'
        }, 'Process': {
            'Start': 'start',
            'Stop': 'end'
        }, 'RPC': {
            'ServerCallStart': '',
            'ServerCallEnd': '',
            'ClientCallEnd': '',
            'ClientCallStart': ''
        }, 'Image': {
            'Load': '',
            'Unload': ''
        }
    }
    # 日志文件夹路径
    logDirPath = "./logs"

    def __init__(self):
        self.params.append(self.wtracePath)
        self.clientPid = os.getpid()
        if self.isApplyNoSummary:
            self.params.append(self.summaryParam)
        if self.isApplyHandlers:
            self.params.append("--handlers")
            self.params.append(self.handlersParam)
        if self.isApplyFilter:
            for filt in self.filtersParams:
                self.params.append("-f")
                self.params.append(filt)
        if not os.path.exists(self.logDirPath):
            os.mkdir(self.logDirPath)

    def run(self):
        # 与服务器建立连接，获取处理本客户端数据的端口号
        self.getPort()
        logQueue = queue.Queue()
        fileQueue = queue.Queue()
        print("[+] {} Client online.".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())))
        monitorThread = threading.Thread(target=self.monitorThreadWork, args=(logQueue,))
        parseThread = threading.Thread(target=self.parseThreadWork, args=(logQueue, fileQueue))
        transferThread = threading.Thread(target=self.transferThreadWork, args=(fileQueue,))
        monitorThread.start()
        parseThread.start()
        transferThread.start()
        ##########
        time.sleep(20)
        self.stop = True
        ##########
        ##########
        # while True:
        #     s = input()
        #     if s == "stop":
        #         self.stop = True
        #         print("[*] {} Client offline.".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())))
        #         break
        #     else:
        #         print("[-] {} Error input. You should input stop instead of '{}'.".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), s))
        #########

    def getPort(self):
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverSocket.connect((self.host, self.serverPort))
        macString = uuid.uuid1().hex[-12:]
        ipString = socket.gethostbyname(socket.gethostname())
        self.token = hashlib.md5((getIPHexStr(ipString) + macString).encode()).hexdigest()
        serverSocket.send(macString.encode())
        self.chServerPort = int(serverSocket.recv(5).decode())
        serverSocket.close()

    def monitorThreadWork(self, logQueue):
        print("[+] {} Monitor thread start working.".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())))
        monitorProcess = subprocess.Popen(self.params, stdout=subprocess.PIPE)
        self.wtracePid = monitorProcess.pid
        while not self.stop:
            logQueue.put(monitorProcess.stdout.readline())
        monitorProcess.terminate()
        print("[*] {} Monitor process stop monitoring.".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())))
        while True:
            log = monitorProcess.stdout.readline()
            if len(log) > 0:
                logQueue.put(log)
            else:
                break
        self.finishMonitor = True
        print("[*] {} Monitor thread stop working.".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())))

    def parseThreadWork(self, logQueue, fileQueue):
        print("[+] {} Parse thread start wokring.".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())))
        logPath = None
        # 停止命令发送前以1000条数据为界限，记录日志
        while not self.stop:
            logIndex = 0
            logFileIndex = 0
            logFileName = time.strftime("%Y_%m_%d_%H_%M_%S_{}.json".format(logFileIndex), time.localtime(time.time()))
            logPath = "{}/{}".format(self.logDirPath, logFileName)
            while os.path.exists(logPath):
                logFileIndex += 1
                logFileName = time.strftime("%Y_%m_%d_%H_%M_%S_{}.json".format(logFileIndex), time.localtime(time.time()))
                logPath = "{}/{}".format(self.logDirPath, logFileName)
            logFile = open(logPath, "w")
            while logIndex < 1000 and not self.stop:
                try:
                    line = logQueue.get()
                    log = self.fromLogString2Json(line.decode("gbk"))
                    if log != "":
                        logFile.write(log)
                        logIndex += 1
                    del line
                except queue.Empty as e:
                    time.sleep(0.2)
            logFile.close()
            fileQueue.put(logPath)
            print("[+] {} Parse thread stored {:>5} logs to {}.".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), logIndex, logPath))
        # 停止命令发送后，创建文件将未来得及记录的日志信息保存
        logIndex = 0
        logFileIndex = 0
        if logPath != None:
            logFileName = time.strftime("%Y_%m_%d_%H_%M_%S_{}.json".format(logFileIndex), time.localtime(time.time()))
            logPath = "{}/{}".format(self.logDirPath, logFileName)
            while os.path.exists(logPath):
                logFileIndex += 1
                logFileName = time.strftime("%Y_%m_%d_%H_%M_%S_{}.json".format(logFileIndex), time.localtime(time.time()))
                logPath = "{}/{}".format(self.logDirPath, logFileName)
            logFile = open(logPath, "w")
            time.sleep(0.1)
            while not logQueue.empty() or not self.finishMonitor:
                line = logQueue.get()
                log = self.fromLogString2Json(line.decode("gbk"))
                if log != "":
                    logFile.write(log)
                    logIndex += 1
                del line
            logFile.close()
            fileQueue.put(logPath)
            self.finishParse = True
            print("[+] {} Parse thread stored {:>5} logs to {}.".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), logIndex, logPath))
            print("[*] {} Parse thread stop working.".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())))

    def fromLogString2Json(self, logString):
        timeStamp = ""
        processId = ""
        parentProcessId = ""
        threadId = ""
        processName = ""
        eventName = ""
        operation = ""
        errMsg = ""
        user = ""
        group = ""
        resultDict = {
            "time": timeStamp,
            "procName": processName,
            "pid": processId,
            "ppid": parentProcessId,
            "tid": threadId,
            "eventType": eventName,
            "operation": operation,
            "group": group,
            "user": user,
            "info": {},
            "errmsg": errMsg,
            "source": base64.b64encode(logString.encode()).decode()
        }
        try:
            infos = logString.split('\t')
            # 获取事件类型及时间名
            eventNameList = infos[3].split('/')
            eventType = eventNameList[0]
            eventName = eventNameList[1]
            # 根据事件组名确定事件类型，根据事件名确定操作名
            operation = self.eventDict[eventType][eventName]
            resultDict.update({"operation":operation})
            idList = infos[2].replace('(', '').replace(')', '').split('.')
            processId = int(idList[0])
            threadId = int(idList[1])
            if resultDict["operation"] != "" and processId != self.clientPid and processId != self.wtracePid:
                # 获取时间戳
                timeStamp = datetime.datetime.strptime(infos[0], "%Y-%m-%d %H:%M:%S.%f").timestamp()
                # 获取进程号、线程号以及启动进程的用户
                processName = infos[1]
                # 根据进程id获取启动进程的账号
                if not (eventType == "Process" and operation == "end"):
                    group, user, parentProcessId = self.getUserFromPid(processId)
                # 如果事件名没在预定范围内则不解析该日志，否则根据具体事件类型解析日志
                if eventType == "Process":
                    eventType = "process"
                    resultDict = self.getProcessInfo(resultDict, infos, operation)
                elif eventType == "Thread":
                    eventType = "thread"
                    resultDict = self.getThreadInfo(resultDict, infos, operation)
                elif eventType == "FileIO":
                    eventType = "file"
                    resultDict = self.getFileInfo(resultDict, infos, operation)
                elif eventType == "UdpIp" or eventType == "TcpIp":
                    eventType = "connect"
                    if eventType == "UdpIp":
                        resultDict["info"].update({"prot": "udp"})
                    else:
                        resultDict["info"].update({"prot": "tcp"})
                    resultDict = self.getConnectInfo(resultDict, infos, eventName)
        except Exception as e:
            resultDict.update({"statu": -2, "errmsg": str(e.args)})
        finally:
            if resultDict["operation"] != "" and processId != self.clientPid and processId != self.wtracePid:
                resultDict.update({
                    "time": timeStamp,
                    "procName": processName,
                    "pid": processId,
                    "ppid": parentProcessId,
                    "tid": threadId,
                    "eventType": eventType,
                    "operation": operation,
                    "group": group,
                    "user": user,
                })
                return json.dumps(resultDict) + '\n'
            else:
                return ""

    def getUserFromPid(self, processId):
        try:
            process = psutil.Process(processId)
            parentProcessId = process.ppid()
            userAndGroup = process.username().split('\\')
            return [userAndGroup[0], userAndGroup[1], parentProcessId]
        except psutil.NoSuchProcess:
            return ["", "", ""]

    def getProcessInfo(self, resultDict, infos, operation):
        try:
            cmd = ""
            if "command line" in infos[5]:
                cmd = base64.b64encode(infos[5][16:-1].encode()).decode()
            resultDict.update({"statu": 0, "errmsg": ""})
        except Exception as e:
            resultDict.update({"statu": -2, "errmsg": str(e.args)})
        finally:
            resultDict["info"].update({"cmd": cmd})
            return resultDict

    def getThreadInfo(self, resultDict, infos, operation):
        try:
            name = ""
            if "name" in infos[5]:
                name = infos[5].replace(" name: ", "")
            resultDict.update({"statu": 0, "errmsg": ""})
        except Exception as e:
            resultDict.update({"statu": -2, "errmsg": str(e.args)})
        finally:
            resultDict["info"].update({"name": name})
            return resultDict

    def getFileInfo(self, resultDict, infos, operation):
        try:
            path = ""
            owner = ""
            group = ""
            path = infos[4].replace('\'', '')
            lindex = path.index(' ')
            path = path[lindex + 1:]
            if operation == "delete":
                resultDict.update({"statu": 0})
                resultDict["info"].update({"path": path, "owner": owner, "group": group})
            elif path == "C:\Windows\system32\Logfiles\WMI\RtBackup\EtwRTwtrace-rt.etl" or path == "C:\Windows\system32\logfiles\WMI\RtBackup\EtwRTwtrace-rt.etl":
                resultDict.update({"operation":""})
            else:
                ownerSid = win32security.GetFileSecurity(path, win32security.OWNER_SECURITY_INFORMATION).GetSecurityDescriptorOwner()
                owner, group, __ = win32security.LookupAccountSid("", ownerSid)
                resultDict["info"].update({"path": path, "owner": owner, "group": group})
                resultDict.update({"statu": 0, "errmsg": ""})
        except pywintypes.error as e:
            winErrCodeDict = {
                2: "Can not find the file.",
                3: "Can not find the path.",
                5: "Access denied.",
                32: "Another process is using the file.",
                123: "Illegal path."
            }
            errCode = e.args[0]
            if errCode not in winErrCodeDict.keys():
                errMsg = "Unexcepted error info:{}".format(e.args[2].encode("utf-8").decode("utf-8"))
            else:
                errMsg = winErrCodeDict[errCode]
            resultDict.update({"statu": -1, "errmsg": errMsg})
        except Exception as e:
            resultDict.update({"statu": -2, "errmsg": str(e.args)})
        finally:
            if resultDict["operation"] != "":
                resultDict["info"].update({"path": path, "owner": owner, "group": group})
                return resultDict
            else:
                return resultDict

    def getConnectInfo(self, resultDict, infos, eventName):
        try:
            srcIp = ""
            srcPort = ""
            dstIp = ""
            dstPort = ""
            lQuoteIndex = infos[4].index('\'')
            rQuoteIndex = infos[4].rindex('\'')
            ips = infos[4][lQuoteIndex+1:rQuoteIndex].split(' -> ')
            srcIpInfo = ips[0].split(':')
            dstIpInfo = ips[1].split(':')
            if len(srcIpInfo) == 2:
                srcIp = srcIpInfo[0]
                srcPort = srcIpInfo[1]
            else:
                srcIp = ":".join(srcIpInfo[:-1])
                srcPort = srcIpInfo[-1]
            if len(dstIpInfo) == 2:
                dstIp = dstIpInfo[0]
                dstPort = dstIpInfo[1]
            else:
                dstIp = ":".join(dstIpInfo[:-1])
                dstPort = dstIpInfo[-1]
            resultDict.update({"statu": 0, "errmsg": ""})
        except Exception as e:
            resultDict.update({"statu": -2, "errmsg": str(e.args)})
        finally:
            resultDict["info"].update({"srcIp": srcIp, "srcPort": srcPort, "dstIp": dstIp, "dstPort": dstPort})
            return resultDict

    def transferThreadWork(self, fileQueue):
        print("[+] {} Transfer thread start working.".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())))
        while not self.stop or not fileQueue.empty() or not self.finishMonitor or not self.finishParse:
            while not fileQueue.empty():
                logPath = fileQueue.get()
                serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                serverSocket.connect((self.host, self.chServerPort))
                logName = logPath[len(self.logDirPath)+1:]
                serverSocket.send(logName.encode())
                jsonFile = open(logPath, "rb")
                buff = jsonFile.read(self.buffSize)
                while len(buff) > 0:
                    serverSocket.send(buff)
                    del buff
                    buff = jsonFile.read(self.buffSize)
                print("[+] {} Tranfered {} to child server {}:{}.".format(
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                    logName,
                    self.host,
                    self.chServerPort
                ))
                serverSocket.close()
                jsonFile.close()
                time.sleep(0.5)
                while True:
                    try:
                        os.remove(logPath)
                        break
                    except PermissionError as e:
                        if e.args[2] == 32:
                            continue
                        else:
                            raise e
            if not self.stop:
                serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                serverSocket.connect((self.host, self.chServerPort))
                serverSocket.send("suspend".encode())
                serverSocket.close()
                time.sleep(7)
        print("[*] {} Transfer thread stop working.".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())))


if __name__ == "__main__":
    client = kernelMonitorClient()
    client.run()
