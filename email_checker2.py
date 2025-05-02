
import csv
import email
import poplib
import socket
import ssl
import socks
import sys
import time

import requests

from email.parser import Parser
from email.header import decode_header
from email.utils import parseaddr
from threading import Thread,Lock


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
    def fetch_emails(email_address, password,proxy_host,proxy_port,proxy_username,proxy_password):
        server = ProxiedPOP3_SSL('pop.163.com',proxy_host=proxy_host,proxy_port=proxy_port,proxy_username=proxy_username,proxy_password=proxy_password)
        
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
    
    @staticmethod
    def fetch_email_proxy(email_address,password,proxy_host,proxy_port,proxy_username,proxy_password):
        #  socks5://d0f1e2274a:2ecb26e7b8@qudns.cc:33115
        url = 'http://156.225.20.47:8080/getEmail?server=%s&user=%s&pass=%s&proxy=socks5://%s:%s@%s:%s&ssl=true' % \
               ('pop.163.com',email_address,password,proxy_username,proxy_password,proxy_host,proxy_port)
        resp = requests.get(url,timeout=5).json()
        
        if not resp.get('success'):
            return []
        

        emails = []
        for i in resp.get('messages'):
            try:
                msg_content = '\r\n' + i.get('content')
                msg = Parser().parsestr(msg_content)
                
                email_data = email_reader.parse_email_content(msg)
                #email_data['index'] = i
                emails.append(email_data)
            except:
                pass

        return emails


thread_lock = Lock()
except_list = []
ok_list = []

def check_thread(row_data):
    email_address = row_data['email']
    email_password = row_data['password']
    proxy_info = row_data['proxy']

    if '@' in  proxy_info:
        a,b= proxy_info.split('@')
        proxy_username,proxy_password = a.split(':')
        proxy_host,proxy_port = b.split(':')
    else:
        proxy_host,proxy_port,proxy_username,proxy_password = proxy_info.split(':')

    try:
        #print(email_address,proxy_host)
        emails = email_reader.fetch_email_proxy(email_address,email_password,proxy_host,proxy_port,proxy_username,proxy_password)
        print('OK',email_address)
        thread_lock.acquire()
        ok_list.append(email_address)
        thread_lock.release()
    except socks.SOCKS5AuthError:
        print('ERR> proxy auth fail',email_address)
        thread_lock.acquire()
        except_list.append((email_address,'proxy auth fail'))
        thread_lock.release()
    except socks.GeneralProxyError:
        print('ERR> proxy auth fail',email_address)
        thread_lock.acquire()
        except_list.append((email_address,'proxy auth fail'))
        thread_lock.release()
    except TimeoutError:
        print('ERR> proxy timeout',email_address)
        thread_lock.acquire()
        except_list.append((email_address,'proxy timeout'))
        thread_lock.release()
    except poplib.error_proto as err:
        err_str = str(err)
        import re
        byte_str_match = re.search(r"b'(.*?)'", err_str)
        byte_str_content = "b'" + byte_str_match.group(1) + "'"
        byte_obj = eval(byte_str_content)
        print('ERR>',byte_obj.decode('gbk'),email_address)
        thread_lock.acquire()
        except_list.append((email_address,byte_obj.decode('gbk')))
        thread_lock.release()
    except Exception as err:
        print('ERR> Unknow',email_address)
        thread_lock.acquire()
        except_list.append((email_address,'Unknow'))
        thread_lock.release()

def ttx_thread(row_data):
    email_address = row_data['email']
    email_password = row_data['password']
    proxy_info = row_data['proxy']

    if '@' in  proxy_info:
        a,b= proxy_info.split('@')
        proxy_username,proxy_password = a.split(':')
        proxy_host,proxy_port = b.split(':')
    else:
        proxy_host,proxy_port,proxy_username,proxy_password = proxy_info.split(':')

    try:
        #print(email_address,proxy_host)
        emails = email_reader.fetch_email_proxy(email_address,email_password,proxy_host,proxy_port,proxy_username,proxy_password)

        for email in emails:
            print(email.keys())
            print(email.get('content'))# == 'System verification code')
    except:
        return False

if __name__ == '__main__':
    if len(sys.argv) > 2:
        if not sys.argv[1] in ['check','ttx']:
            print('python3 ./email_checker.py check|ttx ./email_checker.csv')
            exit()

        with open(sys.argv[2], 'r', encoding='utf-8') as file:
            thread_list = []
            csv_reader = csv.DictReader(file)
            

            for row in csv_reader:
                ttx_thread(row)
                exit()
                if 'check' == sys.argv[1]:
                    thread_imp = Thread(target=check_thread,args=(row,))
                else:
                    thread_imp = Thread(target=ttx_thread,args=(row,))
                thread_imp.start()
                thread_list.append(thread_imp)
                time.sleep(0.1)

            for thread_imp in thread_list:
                thread_imp.join()
    else:
        print('python3 ./email_checker.py check|ttx ./email_checker.csv')
        exit()
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

