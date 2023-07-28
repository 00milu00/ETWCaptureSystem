# coding=utf-8

import hashlib
import multiprocessing
import os
import socket
import threading
import time

import psycopg2

import chProcess


def getIPHexStr(clientip):
    ipNums = [int(num) for num in clientip.split('.')]
    ipHexNums = []
    for num in ipNums:
        if len(hex(num)[2:]) < 2:
            ipHexNums.append('0' + hex(num)[2:])
        else:
            ipHexNums.append(hex(num)[2:])
    return "".join(ipHexNums)


class kernelMonitorServer:
    # 数据库服务器的ip地址与端口
    host = "192.168.16.130"
    serverPort = 12345
    dbPort = 5432
    dbUsername = "postgres"
    dbPassword = "Aa000000."
    db = "postgres"
    # 映射表
    mapTableInfos = {}
    updateTime = 10
    closeTime = 30 * 60
    # 队列
    lastRunTimeQueue = None
    # 可用端口
    freePorts = []
    # 日志文件文件夹路径
    logDirPath = "./logs"
    mapPath = "./map.txt"
    # 传输缓冲区大小
    buffSize = 4096

    def __init__(self):
        self.lastRunTimeQueue = multiprocessing.Queue()
        self.freePorts = [1 if index <= self.serverPort else 0 for index in range(65536)]
        # 判断日志文件夹是否存在
        if not os.path.exists(self.logDirPath):
            os.mkdir(self.logDirPath)
        # 创建监控线程，检查线程活跃时间是否超时
        updateLastRunTimeThread = threading.Thread(target=self.updateLastRunTime)
        updateLastRunTimeThread.daemon = True
        updateLastRunTimeThread.start()
        if not os.path.exists(self.mapPath):
            mapFile = open(self.mapPath, "w")
            mapFile.close()

    def run(self):
        # 服务端启动并循环接收连接请求
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverSocket.bind((self.host, self.serverPort))
        print("[+] {} Server online.".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())))
        serverSocket.listen(5)
        while True:
            clientSocket, clientAddr = serverSocket.accept()
            clientMac = clientSocket.recv(12).decode()
            clientIp = clientAddr[0]
            clientToken = hashlib.md5((getIPHexStr(clientIp) + clientMac).encode()).hexdigest()
            self.updateMapInfo(clientIp, clientMac, clientToken)
            print("[+] {} Created child server {}:{} to deal the connection from {}({}).".format(
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                self.host,
                self.mapTableInfos[clientToken]["port"],
                clientIp,
                clientMac))
            clientSocket.send(str(self.mapTableInfos[clientToken]["port"]).encode())
            clientSocket.close()

    def updateMapInfo(self, clientIp, clientMac, clientToken):
        currentTime = time.time()
        agents = self.mapTableInfos.keys()
        # 判断主机信息是否在映射表中
        if clientToken in agents:
            infoString = clientToken + ' ' + str(currentTime)
            self.lastRunTimeQueue.put(infoString)
            if self.mapTableInfos[clientToken]["chProc"] == None:
                port = self.getPort()
                chProc = multiprocessing.Process(
                    target=self.createNewProc,
                    args=(
                        self.host,
                        port,
                        self.dbPort,
                        self.dbUsername,
                        self.dbPassword,
                        clientToken,
                        self.lastRunTimeQueue,
                        self.logDirPath,
                        self.buffSize
                    ))
                self.mapTableInfos[clientToken].update({"chProc":chProc, "port": port})
                chProc.daemon = True
                chProc.start()
        else:
            # 判断是否创建临时文件夹
            if not os.path.exists("{}/{}".format(self.logDirPath, clientToken)):
                os.mkdir("{}/{}".format(self.logDirPath, clientToken))
            mapFile = open(self.mapPath, "a")
            mapFile.write("{}\t{}\t{}\n".format(clientIp, clientMac, clientToken))
            mapFile.close()
            # 创建数据库
            databaseConn = psycopg2.connect(
                database=self.db,
                host=self.host,
                port=self.dbPort,
                user=self.dbUsername,
                password=self.dbPassword
            )
            databaseConn.set_session(autocommit=True)
            databaseCur = databaseConn.cursor()
            databaseCur.execute("select  * from pg_catalog.pg_database where datname='agent_{}';".format(clientToken))
            if databaseCur.fetchall() == []:
                databaseCur.execute("create database agent_{};".format(clientToken))
            databaseCur.close()
            databaseConn.close()
            # 获取空闲端口
            port = self.getPort()
            # 创建子服务器线程
            chProc = multiprocessing.Process(
                target=self.createNewProc,
                args=(
                    self.host,
                    port,
                    self.dbPort,
                    self.dbUsername,
                    self.dbPassword,
                    clientToken,
                    self.lastRunTimeQueue,
                    self.logDirPath,
                    self.buffSize
                ))
            chProc.daemon = True
            chProc.start()
            # 更新映射表
            agentId = len(agents) + 1
            agentInfo = {
                "agentId": agentId,
                "clientIp": clientIp,
                "clientMac": clientMac,
                "lastRunTime": currentTime,
                "chProc": chProc,
                "port": port
            }
            self.mapTableInfos.update({clientToken: agentInfo})

    def updateLastRunTime(self):
        while True:
            currentTime = time.time()
            while not self.lastRunTimeQueue.empty():
                infoString = self.lastRunTimeQueue.get()
                clientToken, lastRunTime = infoString.split(' ')
                self.mapTableInfos[clientToken].update({"lastRunTime": currentTime})
            for agentToken in self.mapTableInfos.keys():
                if currentTime - self.mapTableInfos[agentToken]["lastRunTime"] > self.closeTime:
                    if self.mapTableInfos[agentToken]["chProc"] != None:
                        self.mapTableInfos[agentToken]["chProc"].terminate()
                        print("[*] {} Child server {}:{} to receive the connection from {}({}) offline.".format(
                            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                            self.host, self.mapTableInfos[agentToken]["port"],
                            self.mapTableInfos[agentToken]["clientIp"],
                            self.mapTableInfos[agentToken]["clientMac"]
                        ))
                        self.freePorts[self.mapTableInfos[agentToken]["port"]] = 0
                        self.mapTableInfos[agentToken].update({"port": -1, "chProc": None})
            time.sleep(self.updateTime)

    def getPort(self):
        freePort = self.freePorts.index(0)
        while True:
            try:
                tmpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                tmpSocket.bind((self.host, freePort))
                tmpSocket.close()
                self.freePorts[freePort] = 1
                return freePort
            except OSError as e:
                if e.errno == 98:
                    freePort += 1
                else:
                    raise e

    def createNewProc(self, host, chServerPort, dbPort, dbUname, dbPasswd, clientToken, lastRunTimeQueue, logDirPath, buffSize):
        chProcClass = chProcess.chProcess(
            host,
            chServerPort,
            dbPort,
            dbUname,
            dbPasswd,
            clientToken,
            lastRunTimeQueue,
            logDirPath,
            buffSize
        )
        chProcClass.run()


if __name__ == "__main__":
    server = kernelMonitorServer()
    server.run()
