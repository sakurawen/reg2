
import csv
import email
import poplib
import socket
import ssl
import socks
import sys
import time
import os

from email.parser import Parser
from email.header import decode_header
from email.utils import parseaddr
from threading import Thread,Lock

results = []
results_lock = Lock()

original_socket = socket.socket


class ProxiedPOP3_SSL(poplib.POP3_SSL):

    def __init__(self, host, port=995, keyfile=None, certfile=None, 
                 timeout=15, context=None,proxy_host=None,proxy_port=None,proxy_username=None,proxy_password=None):
        self.host = host
        self.port = port
        self.keyfile = keyfile
        self.certfile = certfile
        self.timeout = timeout
        self._tls_established = True
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        
        if context is None:
            context = ssl._create_stdlib_context(certfile=certfile, keyfile=keyfile)
        
        self.sock = self._create_socket(self.timeout)
        
        self.sock = context.wrap_socket(self.sock, server_hostname=host)
        self.file = self.sock.makefile('rb')
        self._debugging = 0
        self.welcome = self._getresp()

    def _create_socket(self, timeout):
        self.proxy_host = ''
        if self.proxy_host:
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5, self.proxy_host, self.proxy_port, username=self.proxy_username, password=self.proxy_password)
            sock.connect((self.host, self.port))
            sock.settimeout(timeout)
            return sock
        else:
            return socket.create_connection((self.host, self.port), timeout)

class email_reader:

    @staticmethod
    def decode_str(s):
        value, charset = decode_header(s)[0]
        if charset:
            if isinstance(value, bytes):
                value = value.decode(charset)
        return value

    @staticmethod
    def parse_email_content(msg):
        result = {}
        
        result['from'] = parseaddr(msg.get('from'))[1]
        result['to'] = parseaddr(msg.get('to'))[1]
        result['subject'] = email_reader.decode_str(msg.get('Subject', ''))
        
        content = []
        attachments = []
        
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get('Content-Disposition'))
            
            if content_type == 'multipart/alternative':
                continue
                
            if 'attachment' in content_disposition:
                filename = email_reader.decode_str(part.get_filename())
                data = part.get_payload(decode=True)
                attachments.append({
                    'filename': filename,
                    'data': data
                })
            elif content_type == 'text/plain' or content_type == 'text/html':
                body = part.get_payload(decode=True)
                charset = part.get_content_charset()
                if charset:
                    body = body.decode(charset)
                content.append({
                    'type': content_type,
                    'body': body
                })
        
        result['content'] = content
        result['attachments'] = attachments
        return result

    @staticmethod
    def fetch_emails(email_address, password):
        server = ProxiedPOP3_SSL('pop.163.com')
        
        #print(server.getwelcome().decode('utf-8'))
        
        server.user(email_address)
        server.pass_(password)
        
        email_count, total_size = server.stat()
        #print(f'邮件数量: {email_count}, 总大小: {total_size} bytes')
        
        email_to_fetch = min(5, email_count)
        
        emails = []
        for i in range(email_count, email_count - email_to_fetch, -1):
            resp, lines, octets = server.retr(i)
            
            try:
                msg_content = b'\r\n'.join(lines).decode('utf-8')
                msg = Parser().parsestr(msg_content)
                
                email_data = email_reader.parse_email_content(msg)
                email_data['index'] = i
                emails.append(email_data)
            except:
                pass
        
        server.quit()
        
        return emails

pass_count=0
def check_thread(row):
    email_address = row['email']
    email_password = row['email_password']
    global results, results_lock
    result = "失败"
    try:
        emails = email_reader.fetch_emails(email_address, email_password)
        print('OK', email_address)
        result = "成功"
    except socks.SOCKS5AuthError:
        print('ERR> proxy auth fail', email_address)
        result = "失败"
    except socks.GeneralProxyError:
        print('ERR> proxy general fail', email_address)
        result = "失败"
    except TimeoutError:
        print('ERR> proxy timeout', email_address)
        result = "失败"
    except poplib.error_proto as err:
        err_str = str(err)
        import re
        byte_str_match = re.search(r"b'(.*?)'", err_str)
        byte_str_content = "b'" + byte_str_match.group(1) + "'"
        byte_obj = eval(byte_str_content)
        print('ERR>', byte_obj.decode('gbk'), email_address)
        result = "失败"
    except Exception as err:
        print('ERR>', email_address)
        result = "失败"
    with results_lock:
        results.append({
            "email": email_address,
            "email_password": email_password,
            "result": result
        })



if __name__ == '__main__':
    if len(sys.argv) > 1:
        p = os.path.join("csv",f'{sys.argv[1]}.csv')
        with open(p, 'r', encoding='utf-8') as file:
            thread_list = []
            csv_reader = csv.DictReader(file)
            
            for row in csv_reader:
                thread_imp = Thread(target=check_thread,args=(row,))
                thread_imp.start()
                thread_list.append(thread_imp)
                time.sleep(0.1)

            for thread_imp in thread_list:
                thread_imp.join()

        # 写入结果CSV
        with open('result.csv', 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['email', 'email_password', 'result'])
            writer.writeheader()
            with results_lock:
                for row in results:
                    writer.writerow(row)
        print("验证结果已写入 result.csv")
    else:
        email_address = "13458825284@163.com"
        password = "a1234567"  # 注意：使用授权码而不是登录密码
        
        #try:
        emails = email_reader.fetch_emails(email_address, password, '167.100.105.152',7721,'bnvyccgv','nb89qkjbkd8z')
        
        # 打印邮件信息
        for i, email in enumerate(emails):
            print(f"\n--- 邮件 {i+1} ---")
            print(f"发件人: {email['from']}")
            print(f"收件人: {email['to']}")
            print(f"主题: {email['subject']}")
        #except Exception as e:
        #    print(f"发生错误:",e)

