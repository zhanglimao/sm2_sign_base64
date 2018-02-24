# sm2_sign_base64
中国椭圆曲线秘钥算法：sm2摘要认证算法
进入base64_to_key目录执行make，输出test命令，执行test命令输出base64编码的秘钥的认证过程
进入key_to_base64目录执行make，输出test命令，执行test命令输出evp sm2摘要认证经过base64编码的私钥和公钥

依赖库：
  gmssl
  openssl
（当前使用版本GmSSL 2.0 - OpenSSL 1.1.0）
