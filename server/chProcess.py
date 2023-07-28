# coding=utf-8
import base64
import json
import os
import queue
import socket
import threading
import time

import psycopg2


class chProcess:
    host = ""
    serverPort = 0
    dbPort = 0
    dbUname = ""
    dbPasswd = ""
    clientToken = ""
    lastRunTimeQueue = None
    fileQueue = queue.Queue()
    logDirPath = ""
    buffSize = 0

    def __init__(self, ex_host, ex_serverPort, ex_dbPort, ex_uname, ex_passwd, ex_clientToken, ex_lastRunTimeQueue, ex_logDirPath, ex_buffSize):
        self.host = ex_host
        self.serverPort = ex_serverPort
        self.dbPort = ex_dbPort
        self.dbUname = ex_uname
        self.dbPasswd = ex_passwd
        self.clientToken = ex_clientToken
        self.lastRunTimeQueue = ex_lastRunTimeQueue
        self.logDirPath = ex_logDirPath
        self.buffSize = ex_buffSize
        if not os.path.exists("{}/{}/unexcepted.json".format(self.logDirPath, self.clientToken)):
            unexceptedFile = open("{}/{}/unexcepted.json".format(self.logDirPath, self.clientToken), "a")
            unexceptedFile.close()

    def run(self):
        chServerThread = threading.Thread(target=self.chServerThreadWorking)
        chRecordThread = threading.Thread(target=self.chRecordThreadWorking)
        chServerThread.daemon = True
        chRecordThread.daemon = True
        chServerThread.start()
        chRecordThread.start()
        chServerThread.join()
        chRecordThread.join()

    def chServerThreadWorking(self):
        chServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        chServerSocket.bind((self.host, self.serverPort))
        chServerSocket.listen(1)
        print("[+] {} Child server {}:{} online.".format(
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            self.host,
            self.serverPort
        ))
        while True:
            clientSock, clientAddr = chServerSocket.accept()
            self.lastRunTimeQueue.put("{} {}".format(self.clientToken, time.time()))
            recvMsg = clientSock.recv(26).decode()
            if recvMsg == "suspend":
                time.sleep(7)
            else:
                jsonName = recvMsg
                jsonLog = open("{}/{}/{}".format(self.logDirPath, self.clientToken, jsonName), "wb")
                buff = clientSock.recv(self.buffSize)
                while len(buff) > 0:
                    jsonLog.write(buff)
                    del buff
                    buff = clientSock.recv(self.buffSize)
                jsonLog.close()
                print("[+] {} Received a parsed json file {}/{}/{}.".format(
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                    self.logDirPath,
                    self.clientToken,
                    jsonName
                ))
                self.fileQueue.put(jsonName)
                clientSock.close()
                time.sleep(0.5)

    def chRecordThreadWorking(self):
        tableNames = []
        while True:
            while not self.fileQueue.empty():
                # 连接数据库
                databaseConn = psycopg2.connect(
                    database="agent_{}".format(self.clientToken),
                    host=self.host,
                    port=self.dbPort,
                    user=self.dbUname,
                    password=self.dbPasswd
                )
                databaseConn.set_session(autocommit=True)
                databaseCur = databaseConn.cursor()
                databaseCur.execute("select tablename from pg_tables;")
                returnInfos = databaseCur.fetchall()
                for info in returnInfos:
                    tableName = info[0]
                    tableNames.append(tableName)
                tableNames = list(set(tableNames))
                # 判断当前时间对应的数据表
                currentDay = int(time.strftime("%Y%m%d", time.localtime(time.time())))
                if currentDay not in tableNames:
                    self.verifyNeededTable(currentDay, databaseCur)
                    tableNames.append(currentDay)
                jsonName = self.fileQueue.get()
                jsonPath = "{}/{}/{}".format(self.logDirPath, self.clientToken, jsonName)
                jsonFile = open(jsonPath, "r")
                while True:
                    line = jsonFile.readline()
                    if line == "":
                        break
                    else:
                        logJson = json.loads(line.replace('\n', ''))
                        if logJson["statu"] == -2:
                            self.recordUnexceptedLog(
                                base64.b64decode(logJson["source"].encode()).decode(),
                                logJson["errmsg"]
                            )
                        else:
                            tableName = int(int(time.strftime("%Y%m%d", time.localtime(logJson["time"]))))
                            if tableName not in tableNames:
                                self.verifyNeededTable(tableName, databaseCur)
                            try:
                                sqlString = self.json2SqlString(tableName, logJson)
                                databaseCur.execute(sqlString)
                            except Exception as e:
                                self.recordUnexceptedLog(line, str(e))
                                print("[-] {} Unexcepted error: {}".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), e))
                databaseCur.close()
                databaseConn.close()
                print("[+] {} {} stored successfully.".format(
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                    jsonPath))
                os.remove(jsonPath)
            time.sleep(5)

    def recordUnexceptedLog(self, logString, errMsg):
        unexeceptedLogPath = "{}/{}/unexcepted.log".format(self.logDirPath, self.clientToken)
        if not os.path.exists(unexeceptedLogPath):
            unexeceptedLogFile = open(unexeceptedLogPath, "w")
        else:
            unexeceptedLogFile = open(unexeceptedLogPath, "a")
        unexeceptedLogFile.write(errMsg)
        unexeceptedLogFile.write('\r\n')
        unexeceptedLogFile.write(logString)
        unexeceptedLogFile.write('\r\n')
        unexeceptedLogFile.write('\r\n')
        unexeceptedLogFile.close()

    def verifyNeededTable(self, tableName, databaseCur):
        sql2CheckTable = "select  * from pg_tables where tablename='table_{}';".format(tableName)
        databaseCur.execute(sql2CheckTable)
        if len(databaseCur.fetchall()) == 0:
            self.createTable(tableName, databaseCur)

    def createTable(self, tableName, databaseCur):
        sql2CreateTable = '''
        create table table_{}(
            time double precision not null ,
            procName varchar(100) ,
            pid int not null ,
            ppid int ,
            tid int not null ,
            eventType varchar(10) not null ,
            operation varchar(10) not null ,
            procUser varchar(100) ,
            procGroup varchar(100) ,
            path varchar(1000) ,
            fileOwner varchar(100) ,
            fileOwnerGroup varchar(100) ,
            name varchar(100) ,
            cmdLine text ,
            protocol char(3) ,
            srcIp varchar(39) ,
            dstIp varchar(39) ,
            srcPort int ,
            dstPort int ,
            errMsg text , 
            source text ,
            tag text
        );
        '''.format(tableName)
        databaseCur.execute(sql2CreateTable)

    def json2SqlString(self, tableName, logJson):
        timeStamp = logJson["time"]
        procName = "'{}'".format(logJson["procName"]) if logJson["procName"] != "" else "NULL"
        pid = logJson["pid"]
        ppid = "'{}'".format(logJson["ppid"]) if logJson["ppid"] != "" else "NULL"
        tid = logJson["tid"]
        eventType = logJson["eventType"]
        operation = "'{}'".format(logJson["operation"])
        procUser = "'{}'".format(logJson["user"]) if logJson["user"] != "" else "NULL"
        procGroup = "'{}'".format(logJson["group"]) if logJson["group"] != "" else "NULL"
        errmsg = "'{}'".format(logJson["errmsg"]) if logJson["errmsg"] != "" else "NULL"
        source = "'{}'".format(logJson["source"])
        path = owner = ownerGroup = cmd = name = prot = srcIp = dstIp = srcPort = dstPort = "NULL"
        if eventType == "process":
            cmd = "'{}'".format(logJson["info"]["cmd"])
        elif eventType == "thread":
             name = "'{}'".format(logJson["info"]["name"])
        elif eventType == "file":
            path = "'{}'".format(logJson["info"]["path"])
            owner = "'{}'".format(logJson["info"]["owner"])
            ownerGroup = "'{}'".format(logJson["info"]["group"])
        elif eventType == "connect":
            prot = "'{}'".format(logJson["info"]["prot"])
            srcIp = "'{}'".format(logJson["info"]["srcIp"])
            srcPort = "{}".format(logJson["info"]["srcPort"])
            dstIp = "'{}'".format(logJson["info"]["dstIp"])
            dstPort = "{}".format(logJson["info"]["dstPort"])
        eventType = "'{}'".format(logJson["eventType"])
        sqlString = '''
        insert into table_{} (
            time, procname, pid, ppid, tid, eventtype, operation, procuser, procgroup, path, fileowner, fileownergroup, name, cmdline, protocol, srcip, dstip, srcport, dstport, errmsg, source
        ) values (
             {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}
        );
        '''.format(tableName, timeStamp, procName, pid, ppid, tid, eventType, operation, procUser, procGroup, path, owner, ownerGroup, name, cmd, prot, srcIp, dstIp, srcPort, dstPort, errmsg, source)
        return sqlString