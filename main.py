import base64
import json
import requests
import hashlib
import time
from urllib import parse
from crack import Crack
import uuid
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


crack = Crack()
def auth():
    t = str(round(time.time()))
    data = {
        "authKey": hashlib.md5(("testtest" + t).encode()).hexdigest(),
        "timeStamp": t
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Referer": "https://beian.miit.gov.cn/",
        "Content-Type": "application/x-www-form-urlencoded",
        "Connection": "keep-alive",
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Origin": "https://beian.miit.gov.cn"
    }
    try:
        resp = requests.post("https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth", headers=headers,
                             data=parse.urlencode(data)).text
        return json.loads(resp)["params"]["bussiness"]
    except Exception:
        time.sleep(5)
        resp = requests.post("https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth", headers=headers,
                             data=parse.urlencode(data)).text
        return json.loads(resp)["params"]["bussiness"]


def getImage():
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Referer": "https://beian.miit.gov.cn/",
        "Token": token,
        "Connection": "keep-alive",
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Origin": "https://beian.miit.gov.cn"
    }
    payload = {
        "clientUid": "point-" + str(uuid.uuid4())
    }
    try:
        resp = requests.post("https://hlwicpfwc.miit.gov.cn/icpproject_query/api/image/getCheckImagePoint",
                             headers=headers, json=payload).json()
        return resp["params"], payload["clientUid"]
    except Exception:
        time.sleep(5)
        resp = requests.post("https://hlwicpfwc.miit.gov.cn/icpproject_query/api/image/getCheckImagePoint",
                             headers=headers, json=payload).json()
        return resp["params"], payload["clientUid"]


def aes_ecb_encrypt(plaintext: bytes, key: bytes, block_size=16):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)

    padding_length = block_size - (len(plaintext) % block_size)
    plaintext_padded = plaintext + bytes([padding_length]) * padding_length

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext_padded) + encryptor.finalize()

    return base64.b64encode(ciphertext).decode('utf-8')


def generate_pointjson(big_img, small_img, secretKey):
    boxes = False
    
    # if boxes:
    #     print("文字检测成功")
    # else:
    #     print("文字检测失败，正在重试")
    #     boxes = crack.detect(big_img)
    #     return enc_pointJson
    # 判断返回结果是否存在数据，不存在则循环运行：
    while(not boxes):
        boxes = crack.detect(big_img)
        points = crack.siamese(small_img, boxes)
        new_points = [[p[0] + 20, p[1] + 20] for p in points]
        pointJson = [{"x": p[0], "y": p[1]} for p in new_points]
        # print(json.dumps(pointJson))
        enc_pointJson = aes_ecb_encrypt(json.dumps(pointJson).replace(" ", "").encode(), secretKey.encode())
        if boxes:
            print("文字匹配成功")
            return enc_pointJson




def checkImage(uuid_token, secretKey, clientUid, pointJson):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Referer": "https://beian.miit.gov.cn/",
        "Token": token,
        "Connection": "keep-alive",
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Origin": "https://beian.miit.gov.cn"
    }
    data = {
        "token": uuid_token,
        "secretKey": secretKey,
        "clientUid": clientUid,
        "pointJson": pointJson
    }
    resp = requests.post("https://hlwicpfwc.miit.gov.cn/icpproject_query/api/image/checkImage", headers=headers,
                         json=data).json()
    if resp["code"] == 200:
        # print(resp["params"])
        return resp["params"]["sign"]
    return False


def query(sign, uuid_token, domain):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Referer": "https://beian.miit.gov.cn/",
        "Token": token,
        "Sign": sign,
        "Uuid": uuid_token,
        "Connection": "keep-alive",
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Origin": "https://beian.miit.gov.cn",
        "Content-Type": "application/json",
        "Cookie": "__jsluid_s="+str(uuid.uuid4().hex[:32])
    }
    data = {"pageNum": "", "pageSize": "2", "unitName": domain, "serviceType": 1}
    resp = requests.post("https://hlwicpfwc.miit.gov.cn/icpproject_query/api/icpAbbreviateInfo/queryByCondition",
                         headers=headers, data=json.dumps(data).replace(" ","")).text
    return resp


def GetToken():
    global token
    token = auth()
    time.sleep(0.1)
    print("正在获取验证码")
    params, clientUid = getImage()
    pointjson = generate_pointjson(params["bigImage"], params["smallImage"], params["secretKey"])
    time.sleep(0.5)
    sign = checkImage(params["uuid"], params["secretKey"], clientUid, pointjson)
    time.sleep(0.5)
    if sign:
        #print(query(sign, params["uuid"],"北京百度网讯科技有限公司"))
        return sign,params["uuid"]
    else:
        return None

import argparse

if __name__ == '__main__':
    # 解析命令行参数
    parser = argparse.ArgumentParser(description="查询公司信息")
    parser.add_argument('--single', '-s', type=str, help='查询单一目标公司名称')
    parser.add_argument('--file', '-f', type=str, help='批量查询的文件路径')
    parser.add_argument('--output', '-o', type=str, default='results.txt', help='输出结果文件路径')
    
    args = parser.parse_args()

    # 获取Token
    try:
        sign, params = GetToken()
    except Exception as err:
        print(f"获取Token失败: {err}, 正在重试...")
        sign, params = GetToken()

    def process_query(company_name, sign, params):
        """查询指定公司"""
        try:
            return query(sign, params, company_name)
        except Exception as e:
            print(f"查询 {company_name} 时出错: {e}")
            return None

    def batch_process(file_path, sign, params):
        """批量处理查询"""
        # 读取文件中的公司名称
        with open(file_path, 'r', encoding='utf-8') as file:
            companies = file.readlines()
        
        # 去除每行末尾的换行符
        companies = [company.strip() for company in companies]

        # 批量处理
        results = []
        for company in companies:
            print(f"正在查询：{company}")
            result = process_query(company, sign, params)
            if result:
                results.append((company, result))
        
        return results

    def save_results(results, output_file):
        """保存查询结果到文件"""
        with open(output_file, 'w', encoding='utf-8') as file:
            for company, result in results:
                file.write(f"{company} 查询结果: {result}\n")
        print(f"查询结果已保存至 {output_file}")

    results = []

    if args.single:
        # 查询单一公司
        print(f"正在查询单一公司: {args.single}")
        result = process_query(args.single, sign, params)
        if result:
            results.append((args.single, result))
    elif args.file:
        # 批量查询文件中的公司
        print(f"正在批量查询文件中的公司：{args.file}")
        results = batch_process(args.file, sign, params)

    # 输出结果到文件
    if results:
        save_results(results, args.output)
