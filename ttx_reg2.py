
import base64
import csv
import email
import hashlib
import io
import json
import os
import poplib
import random
import socket
import ssl
import socks
import sys
import time

from email.parser import Parser
from email.header import decode_header
from email.utils import parseaddr,parsedate_to_datetime

import requests

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PIL import Image
from tinydb import *


class ttx_smart_client_id:

    def __init__(self):
        self.db_imp = TinyDB('./ttx_client_id.db')

    @staticmethod
    def replace_char_at_index(string, index, new_char):
        if index < 0 or index >= len(string):
            return string
        
        return string[:index] + new_char + string[index+1:]

    @staticmethod
    def create_new_client_id():
        client_id = ''
        char_list = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']

        for _ in range(36):
            client_id += random.choice(char_list)

        client_id = ttx_smart_client_id.replace_char_at_index(client_id,14,'4')
        client_id = ttx_smart_client_id.replace_char_at_index(client_id,19,char_list[ord(client_id[19]) & 3 | 8])
        client_id = ttx_smart_client_id.replace_char_at_index(client_id,8,'-')
        client_id = ttx_smart_client_id.replace_char_at_index(client_id,13,'-')
        client_id = ttx_smart_client_id.replace_char_at_index(client_id,18,'-')
        client_id = ttx_smart_client_id.replace_char_at_index(client_id,23,'-')

        return client_id

    def get_client_id(self,email):
        info = self.db_imp.get(Query().Email == email)

        if info is None:
            info = {
                'Email': email,
                'ClientID': ttx_smart_client_id.create_new_client_id()
            }
            self.db_imp.insert(info)

        return info.get('ClientID')


ttx_smart_client_id_imp = ttx_smart_client_id()


class ttx_smart_account:

    @staticmethod
    def get_location(base64_string):
        if ';base64,' in base64_string:
            base64_string = base64_string.split(';base64,')[1]
        
        image_data = base64.b64decode(base64_string)
        image_buffer = io.BytesIO(image_data)
        image = Image.open(image_buffer)
        #image.save('./captcha.png')
        width, height = image.size
        #print('>',width, height)
        pixels = image.load()
        height_length = 6
        # 218,53
        for width_index in range(width):
            for height_index in range(height):
                if height_index + height_length >= height:
                    break

                is_bingo = False
                tick = 0
                height_location = height_index

                for height_index in range(height_index,height_index + height_length):
                    r = pixels[width_index,height_index][0]
                    g = pixels[width_index,height_index][1]
                    b = pixels[width_index,height_index][2]

                    #print(width_index,height_index,r,g,b)
                    
                    if r == 255 and g == 255 and b == 255:
                        tick += 1

                        if tick >= height_length:
                            width_index += random.randint(0,6)  #  随机的人为抖动
                            width_index = float(width_index) + round(random.random(),3)  #  更符合真的
                            is_bingo = True
                            break
                    else:
                        tick = 0
                        is_bingo = False

                if is_bingo:
                    #new_image = image.crop((width_index,0,width,height))
                    #new_image.save('./captcha_resolve.png')
                    return (width_index,5)   #  5是TTX写死的
            
        return (0,0)
    
    @staticmethod
    def aes_encrypt(plaintext,key):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        cipher = AES.new(key, AES.MODE_ECB)
        padded_data = pad(plaintext, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        
        return base64.b64encode(encrypted_data).decode('utf-8')

    @staticmethod
    def sign(json_data):
        md5_hash = hashlib.md5()
        data = ''
        json_data = {key: json_data[key] for key in sorted(json_data.keys())}
        
        for key,value in json_data.items():
            data += key + '=' + str(value) + '&'

        data += 'key=ACblockandwallets'

        md5_hash.update(data.encode('utf-8'))
        
        return md5_hash.hexdigest().upper()

    @staticmethod
    def convert_proxy_to_requests(proxy_info):
        if proxy_info:
            if '@' in proxy_info:
                a,b= proxy_info.split('@')
                proxy_username,proxy_password = a.split(':')
                proxy_host,proxy_port = b.split(':')
            else:
                proxy_host,proxy_port,proxy_username,proxy_password = proxy_info.split(':')

            return {
                'http': f'socks5://{proxy_username}:{proxy_password}@{proxy_host}:{proxy_port}',
                'https': f'socks5://{proxy_username}:{proxy_password}@{proxy_host}:{proxy_port}',
            }

        return {}

    @staticmethod
    def convert_proxy_to_email(proxy_info):
        if proxy_info:
            proxy_host,proxy_port,proxy_username,proxy_password = proxy_info.split(':')

            return proxy_host,proxy_port,proxy_username,proxy_password
        
        return '','','',''

    def __init__(self,email,email_password,ttx_password,proxy):
        self.session = requests.session()
        self.headers = {
            'user-agent': 'Mozilla/5.0 (Linux; Android 12; 2201123C Build/V417IR; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/91.0.4472.114 Safari/537.36 uni-app Html5Plus/1.0 (Immersed/24.0)'
        }
        self.email = email
        self.email_password = email_password
        self.ttx_password = ttx_password
        self.client_id = ttx_smart_client_id_imp.get_client_id(self.email)
        self.proxy = proxy
        self.access_token = ''
        self.refresh_token = ''
        self.base_host = 'https://sulygmhwwd.esbmmipnpm.com'

    def reg(self,code):
        captcha_get_post_data = {
            'captchaType': 'blockPuzzle',
            'clientUid': 'slider-' + self.client_id,
            'ts': int(time.time() * 1000)
        }
        post_data = self.session.post(self.base_host + '/api/captcha/get',json = captcha_get_post_data,headers = self.headers,proxies = ttx_smart_account.convert_proxy_to_requests(self.proxy)).json()
        catpcha_img = post_data.get('repData').get('originalImageBase64')
        login_token = post_data.get('repData').get('token')
        aes_secret_key = post_data.get('repData').get('secretKey')
        captcha_resolve_location = ttx_smart_account.get_location(catpcha_img)
        
        captchat_check_post_data = {
            'captchaType': 'blockPuzzle',
            'pointJson': ttx_smart_account.aes_encrypt(json.dumps({
                                                                    'x':captcha_resolve_location[0],
                                                                    'y':captcha_resolve_location[1]
                                                                  }).replace(' ',''),aes_secret_key),
            'token': login_token
        }
        post_data = self.session.post(self.base_host + '/api/captcha/check',json = captchat_check_post_data,headers = self.headers,proxies = ttx_smart_account.convert_proxy_to_requests(self.proxy)).json()

        if not post_data.get('success'):
            return False,'Captcha Fail'

        send_sms_post_data = {
            'account': self.email,
            'captchaVerification': ttx_smart_account.aes_encrypt(login_token + '---' + json.dumps({
                                                                    'x':captcha_resolve_location[0],
                                                                    'y':captcha_resolve_location[1]
                                                                  }).replace(' ',''),aes_secret_key),
            'scene': 2,
            'timestamp': int(time.time()),
            
        }
        send_sms_post_data['sign'] = ttx_smart_account.sign(send_sms_post_data)
        post_data = self.session.post(self.base_host + '/api/auth/send_sms',json = send_sms_post_data,headers = self.headers,proxies = ttx_smart_account.convert_proxy_to_requests(self.proxy)).json()

        if not post_data.get('data'):
            return False,'Send SMS Fail'

        time.sleep(3)
        email_code = '678423'
        '''
        proxy_host,proxy_port,proxy_username,proxy_password = ttx_smart_account.convert_proxy_to_email(self.proxy)
        flag = 'Your verification code is: '

        for _ in range(30):
            try:
                emails = email_reader.fetch_email_proxy(self.email,self.email_password,proxy_host,proxy_port,proxy_username,proxy_password)

                if not 'System verification code' == emails[0].get('subject'):
                    continue

                content = emails[0].get('content')[0].get('body')
                email_code = content[content.find(flag) + len(flag):]
                email_code = email_code[:6]
                break
            except:
                pass

            time.sleep(2)
        
        if not email_code:
            return False,'Fetch Email Code Fail'
        '''
        register_login_post_data = {
            'account': self.email,
            'code': email_code,
            'password': self.ttx_password,
            'device': '',
            'is_app': 1,
            'sn': code,
            'captchaVerification': ttx_smart_account.aes_encrypt(login_token + '---' + json.dumps({
                                                                    'x':captcha_resolve_location[0],
                                                                    'y':captcha_resolve_location[1]
                                                                  }).replace(' ',''),aes_secret_key),
            'language': 'zh_CN',
            'timestamp': int(time.time()),
        }
        register_login_post_data['sign'] = ttx_smart_account.sign(register_login_post_data)
        post_data = self.session.post(self.base_host + '/api/auth/registerAndLogin',json = register_login_post_data,headers = self.headers,proxies = ttx_smart_account.convert_proxy_to_requests(self.proxy)).json()
        
        if not post_data.get('code') == 200:
            print(self.email,post_data)
            return False,'Register Login Fail'

        self.access_token = post_data.get('data').get('accessToken')
        self.refresh_token = post_data.get('data').get('refreshToken')
        self.headers['Authorization'] = self.access_token

        return True,'OK'

    def login(self):
        login_post_data = {
            'account': self.email,
            'password': self.ttx_password,
            'code': '',
            'device': '',
            'timestamp': int(time.time()),
        }
        login_post_data['sign'] = ttx_smart_account.sign(login_post_data)
        post_data = self.session.post(self.base_host + '/api/auth/pwd_login',json = login_post_data,headers = self.headers,proxies = ttx_smart_account.convert_proxy_to_requests(self.proxy)).json()
        
        if not post_data.get('code') == 200:
            self.access_token = ''
            self.refresh_token = ''
            self.headers['Authorization'] = ''
            return False
        else:
            self.access_token = post_data.get('data').get('accessToken')
            self.refresh_token = post_data.get('data').get('refreshToken')
            self.headers['Authorization'] = self.access_token

        return True

    def get_balance(self):
        get_data = self.session.get(self.base_host + '/api/user/center',headers = self.headers,proxies = ttx_smart_account.convert_proxy_to_requests(self.proxy)).json()
        
        if not get_data.get('data'):
            return -1

        return get_data.get('data').get('balance')

    def get_kyc_status(self):
        get_data = self.session.get(self.base_host + '/api/index/isKyc',headers = self.headers,proxies = ttx_smart_account.convert_proxy_to_requests(self.proxy)).json()
        
        return get_data.get('data')

    def upload_cert(self,info_image_path,back_image_path):
        is_kyc = self.get_kyc_status()

        if is_kyc:
            return True,'OK'

        upload_info_cert_url = ''
        upload_back_cert_url = ''

        with open(info_image_path, 'rb') as file:
            file_tuple = (os.path.split(info_image_path)[1], file, 'application/octet-stream')
            files = {'file': file_tuple}
            
            post_data = self.session.post(self.base_host + '/api/user/uploadPrimaryImg',files = files,headers = self.headers,proxies = ttx_smart_account.convert_proxy_to_requests(self.proxy)).json()
            print(file_tuple,post_data)
            if not post_data.get('code') == 200:
                return False,'Upload Primary Info'
            
            upload_info_cert_url = post_data.get('data')

        with open(back_image_path, 'rb') as file:
            file_tuple = (os.path.split(back_image_path)[1], file, 'application/octet-stream')
            files = {'file': file_tuple}
            post_data = self.session.post(self.base_host + '/api/user/uploadSecondaryImg',files = files,headers = self.headers,proxies = ttx_smart_account.convert_proxy_to_requests(self.proxy)).json()
            print(file_tuple,post_data)
            if not post_data.get('code') == 200:
                return False,'Upload Secondary Info'
            
            upload_back_cert_url = post_data.get('data')

        submit_kyc_post_data = {
            'residenceCountry':'',
            'country':'',
            'certificateType':'1',
            'imgPrimary':upload_info_cert_url,
            'imgSecondary':upload_back_cert_url,
            'timestamp': int(time.time()),
        }
        submit_kyc_post_data['sign'] = ttx_smart_account.sign(submit_kyc_post_data)
        post_data = self.session.post(self.base_host + '/api/user/kyc',json = submit_kyc_post_data,headers = self.headers,proxies = ttx_smart_account.convert_proxy_to_requests(self.proxy)).json()

        if not post_data.get('code') == 200:
            return False,'Submit Kyc'

        return True,'Upload Success'


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
    def fetch_emails(server,email_address, password, limit=10):
        #print(server.getwelcome().decode('utf-8'))
        
        server.user(email_address)
        server.pass_(password)
        
        email_count, total_size = server.stat()
        #print(f'邮件数量: {email_count}, 总大小: {total_size} bytes')
        
        email_to_fetch = min(limit, email_count)
        
        emails = []
        for i in range(email_count, email_count - email_to_fetch, -1):
            resp, lines, octets = server.retr(i)
            
            msg_content = b'\r\n'.join(lines).decode('utf-8')
            msg = Parser().parsestr(msg_content)
            
            email_data = email_reader.parse_email_content(msg)
            email_data['index'] = i
            emails.append(email_data)
        
        server.quit()
        
        return emails

    @staticmethod
    def fetch_emails_no_proxy(email_address, password):
        server = poplib.POP3_SSL('mail.mikios.shop')#pop.163.com')
        return email_reader.fetch_emails(server,email_address, password, 5)
        
    @staticmethod
    def fetch_emails_by_proxy(email_address, password, proxy_host,proxy_port,proxy_username,proxy_password):
        server = ProxiedPOP3_SSL('pop.163.com',proxy_host=proxy_host,proxy_port=proxy_port,proxy_username=proxy_username,proxy_password=proxy_password)
        return email_reader.fetch_emails(server,email_address, password, 5)
        
    @staticmethod
    def fetch_email_proxy(email_address,password,proxy_host,proxy_port,proxy_username,proxy_password):
        #  socks5://d0f1e2274a:2ecb26e7b8@qudns.cc:33115
        url = 'http://156.225.20.47:8080/getEmail?server=%s&user=%s&pass=%s&proxy=socks5://%s:%s@%s:%s&ssl=true' % \
               ('pop.163.com',email_address,password,proxy_username,proxy_password,proxy_host,proxy_port)
        resp = requests.get(url).json()
        
        if not resp.get('success'):
            return []
        

        emails = []
        for i in resp.get('messages'):
            try:
                msg_content = '\r\n' + i.get('content')
                msg = Parser().parsestr(msg_content)
                
                email_data = email_reader.parse_email_content(msg)
                email_data['index'] = i
                emails.append(email_data)
            except:
                pass

        return emails




thread_lock = Lock()
thread_result = []


def thread_reg(csv_row_data,thread_index):
    global thread_list,thread_lock

    email = csv_row_data.get('email')
    email_password = csv_row_data.get('email_password')
    login_password = csv_row_data.get('password') or 'Qq113355!'
    proxy_info = csv_row_data.get('proxy')
    code = csv_row_data.get('code')
    cert_a_filename = '311746192862_.pic.jpg'
    cert_b_filename = '311746192862_.pic_thumb.jpg'

    if not email:
        print('第%d条信息找不到邮箱 - 账号:%s' % (thread_index,email))
        return
    elif not email_password:
        print('第%d条信息找不到邮箱POP3登录密码 - 账号:%s' % (thread_index,email))
        return
    elif not login_password:
        print('第%d条信息找不到登录密码 - 账号:%s' % (thread_index,email))
        return
    elif not code:
        print('第%d条信息找不到邀请码 - 账号:%s' % (thread_index,email))
        return
    elif not cert_a_filename or not cert_b_filename:
        print('第%d条信息身份证正反面文件名 - 账号:%s' % (thread_index,email))
        return

    cert_a_path = os.path.join('cert',cert_a_filename)
    cert_b_path = os.path.join('cert',cert_b_filename)

    if not os.path.exists(cert_a_path) or not os.path.exists(cert_b_path):
        print('第%d条信息找不到身份证正反面文件 - 账号:%s' % (thread_index,email))
        return

    if not proxy_info:
        proxy_info = ''

    ttx_smart_account_imp = ttx_smart_account(email,email_password,login_password,proxy_info)   #  'zhiping202503@163.com','Lz6388361','123123123',proxy_info)

    print('账号:%s 正在尝试登录' % (email))

    if not ttx_smart_account_imp.login():  #  不能登录
        print('账号:%s 注册中' % (email))
        ttx_reg_status,err_message = ttx_smart_account_imp.reg(code)

        if not ttx_reg_status:
            print('账号:%s 注册失败,原因:%s'  % (email,err_message))
            return

    
    is_kyc = ttx_smart_account_imp.get_kyc_status()

    if is_kyc:
        print('账号:%s 已经上传了证件'  % (email))
        return
    
    upload_cert_status,err_message = ttx_smart_account_imp.upload_cert(cert_a_path,cert_b_path)

    if not upload_cert_status:
        print('账号:%s 上传证件失败,原因:%s'  % (email,err_message))
        return
    
    print('账号:%s 上传证件成功'  % (email))


def thread_get_balance(csv_row_data,thread_index):
    global thread_list,thread_lock

    email = csv_row_data.get('email')
    email_password = csv_row_data.get('email_password')
    login_password = csv_row_data.get('password')
    proxy_info = csv_row_data.get('proxy')

    ttx_smart_account_imp = ttx_smart_account(email,email_password,login_password,proxy_info)

    if not ttx_smart_account_imp.login():
        print('第%d条信息登录失败 - 账号:%s' % (thread_index,email))
        exit()

    is_kyc = ttx_smart_account_imp.get_kyc_status()
    balance = ttx_smart_account_imp.get_balance()

    print('账号:%s 已通过Kyc:%s 余额:%0.2f' % (email,is_kyc,float(balance)))


if __name__ == '__main__':
    if len(sys.argv) == 3:
        if not sys.argv[1] in ['reg','balance']:
            print('Using: python3 ttx_reg.py reg xxx.csv')
            exit()
        csv_path = os.path.join('csv',f'{sys.argv[2]}.csv')
        print(f'{csv_path=}')
        with open(csv_path, 'r', encoding='utf-8') as file:
            thread_list = []
            csv_reader = csv.DictReader(file)
            thread_index = 1
            
            for row in csv_reader:
                if 'reg' == sys.argv[1]:
                    thread_imp = Thread(target=thread_reg,args=(row,thread_index))
                else:
                    thread_imp = Thread(target=thread_get_balance,args=(row,thread_index))

                thread_imp.start()
                thread_list.append(thread_imp)
                thread_index += 1
                time.sleep(0.1)

            for thread_imp in thread_list:
                thread_imp.join()


    exit()
    
    email_address = "lqcqgnwxke@mikios.shop"
    password = "wWmKCFG90efe2614f91b2c6"  # 注意：使用授权码而不是登录密码
    	
    try:
        emails = email_reader.fetch_emails_no_proxy(email_address, password)
        
        # 打印邮件信息
        for i, email in enumerate(emails):
            print(f"\n--- 邮件 {i+1} ---")
            print(f"发件人: {email['from']}")
            print(f"收件人: {email['to']}")
            print(f"主题: {email['subject']}")
    except Exception as e:
        print(f"发生错误:",e)


