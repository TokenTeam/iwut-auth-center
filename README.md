# 吾理经纬 用户中心
## 项目开发
```bash
make init
make all
```
这两行命令实际上完成了：依赖拉取、proto 代码生成、wire 依赖注入代码生成等工作。
你可以到 `Makefile` 中查看具体实现。
## 环境变量
想要了解有哪些可以配置的环境变量，你应当检查 `configs/config.yaml` 文件。
其中，以mongoDB URI为例：其格式如下：
```yaml
uri: "${mongoUrl:mongodb://localhost:27017/}"
```
为了使用环境变量覆盖该值，对应环境变量的键是`AuthCenter_mongoUrl`。即使用`AuthCenter_`作为前缀，后接配置文件中的变量名。

需要注意的是，在生产环境中部署时，你需要替换`jwt.key.private_key`和`jwt.key.public_key`的值。
生成私钥和公钥的命令如下：
```bash
# 生成私钥
openssl genrsa -out rsa-private-key.pem 2048
# 生成公钥
openssl rsa -in rsa-private-key.pem -pubout -out rsa-public-key.pem
```
这会在你当前文件夹下生成`rsa-private-key.pem`和`rsa-public-key.pem`两个文件。
尽管程序支持且自动识别值是否经过BASE64编码，但在生产环境中，建议你使用BASE64编码后的值作为环境变量传入。

## Docker
```bash
# build
docker build -t <your-docker-image-name> .

# run
docker run --rm -p 8000:8000 -p 9000:9000 -v </path/to/your/configs>:/data/conf <your-docker-image-name>
```

