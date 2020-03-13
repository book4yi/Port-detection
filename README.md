# Port-detection
Port-detection用于批量探测端口开放情况  
## 功能：  
1. 结合了masscan的扫描速度和nmap的端口识别功能  
2. 若开放了80和443端口，会进行访问并获取相关页面信息（标题、脚本语言等等）  
3. 结果保存在txt文件中  
## 用法：
```
python　Port_detection.py　--target　[urls file]
已附带windows下使用的masscan，结合自身情况更改masscan路径
```


