import base64
import csv
import email
import os
import poplib
import socket
import ssl
import socks
import sys
import time
from email.parser import Parser
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime

USE_PROXY = False  # 设置为 False 时不使用代理

class ProxiedPOP3_SSL(poplib.POP3_SSL):
    def __init__(self, host, port=995, keyfile=None, certfile=None, 
                 timeout=15, context=None, proxy_host=None, proxy_port=None, proxy_username=None, proxy_password=None):
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
        if USE_PROXY and self.proxy_host:
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5, self.proxy_host, self.proxy_port, username=self.proxy_username, password=self.proxy_password)
            sock.connect((self.host, self.port))
            sock.settimeout(timeout)
            return sock
        else:
            return socket.create_connection((self.host, self.port), timeout)

class EmailReader:
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
        result['subject'] = EmailReader.decode_str(msg.get('Subject', ''))
        date_str = msg.get('Date')
        date_time = parsedate_to_datetime(date_str)
        result['timestamp'] = date_time.timestamp()
        content = []
        attachments = []
        
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get('Content-Disposition'))
            
            if content_type == 'multipart/alternative':
                continue
            
            if 'attachment' in content_disposition:
                filename = part.get_filename()
                if not filename:
                    filename = 'unknown'
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
    def fetch_emails(server, email_address, password, limit=10):
        server.user(email_address)
        server.pass_(password)
        
        email_count, total_size = server.stat()
        email_to_fetch = min(limit, email_count)
        
        emails = []
        for i in range(email_count, email_count - email_to_fetch, -1):
            resp, lines, octets = server.retr(i)
            msg_content = b'\r\n'.join(lines).decode('utf-8')
            msg = Parser().parsestr(msg_content)
            
            email_data = EmailReader.parse_email_content(msg)
            email_data['index'] = i
            emails.append(email_data)
        
        server.quit()
        return emails

    @staticmethod
    def fetch_emails_no_proxy(email_address, password):
        server = poplib.POP3_SSL('pop.163.com')
        return EmailReader.fetch_emails(server, email_address, password, 5)

    @staticmethod
    def fetch_emails_by_proxy(email_address, password, proxy_host, proxy_port, proxy_username, proxy_password):
        server = ProxiedPOP3_SSL('pop.163.com', proxy_host=proxy_host, proxy_port=proxy_port,
                                proxy_username=proxy_username, proxy_password=proxy_password)
        return EmailReader.fetch_emails(server, email_address, password, 5)

def convert_proxy_to_email(proxy_info):
    if not USE_PROXY or not proxy_info:
        return '', '', '', ''
    proxy_host, proxy_port, proxy_username, proxy_password = proxy_info.split(':')
    return proxy_host, proxy_port, proxy_username, proxy_password

def wait_for_email_code(email, email_password, proxy_info=None):
    """等待并获取邮箱验证码"""
    proxy_host, proxy_port, proxy_username, proxy_password = convert_proxy_to_email(proxy_info)
    
    try:
        if proxy_info:
            emails = EmailReader.fetch_emails_by_proxy(email, email_password, proxy_host, proxy_port, proxy_username, proxy_password)
        else:
            emails = EmailReader.fetch_emails_no_proxy(email, email_password)
        
        if not emails:
            print("未找到任何邮件")
            return None
            
        current_time = time.time()
        five_minutes = 5 * 60  # 5分钟的秒数
        found_verification_email = False
            
        # 查找主题为验证码的邮件
        for email_data in emails:
            # 检查邮件时间
            email_time = email_data.get('timestamp')
            if 'System verification code' == email_data.get('subject'):
                found_verification_email = True
                if current_time - email_time > five_minutes:
                    print(f"找到验证码邮件，但发送时间超过5分钟（{int((current_time - email_time) / 60)}分钟前）")
                    continue

                content = email_data.get('content')[0].get('body')
                flag = 'Your verification code is: '
                if flag in content:
                    code = content[content.find(flag) + len(flag):content.find(flag) + len(flag) + 6]
                    return code
                else:
                    print("邮件内容中未找到验证码")
        
        if not found_verification_email:
            print("未找到主题为'System verification code'的邮件")
            
    except Exception as e:
        print(f"读取邮件出错: {str(e)}")
    return None

def main():
    if len(sys.argv) != 2:
        print('Usage: python3 email_code_reader.py xxx.csv')
        return
        
    csv_path = os.path.join('csv',f'{sys.argv[1]}.csv')
    if not os.path.exists(csv_path):
        print(f"File not found: {csv_path}")
        return
        
    with open(csv_path, 'r', encoding='utf-8') as file:
        csv_reader = csv.DictReader(file)
        
        for row in csv_reader:
            email = row.get('email')
            email_password = row.get('email_password')
            proxy = row.get('proxy')  # 可选的代理设置
            
            if not email or not email_password:
                print(f"Skipping invalid row: missing email or password")
                continue
                
            print(f"\n即将处理邮箱: {email}")
            input("按回车开始获取验证码...")
            print("等待验证码...")
            
            # 尝试多次获取验证码
            for attempt in range(30):
                code = wait_for_email_code(email, email_password, proxy)
                if code:
                    print(f"收到验证码: {code}")
                    break
                time.sleep(2)
            else:
                print("未能获取到验证码")
            
            if csv_reader.line_num < sum(1 for row in csv.DictReader(open(csv_path, 'r', encoding='utf-8'))):
                input("按回车继续下一个邮箱...")
            else:
                print("\n所有邮箱处理完成")

if __name__ == '__main__':
    main()
