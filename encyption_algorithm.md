# 加密算法

#### 概述

* 加密算法分为**单向加密**和**双向加密**，明文数据通过加密后传输，以确保传输和存储安全
* 单向加密()即不可逆的加密方式，就是无法将加密后的数据恢复成原始数据，如：MD5、SHA、BCrypt加密算法
* 双向加密即可逆的加密方式，**存在密文的秘钥**，持有密文的一方可以根据秘钥解密从而得到明文，一般用于发送方和接收方都能通过秘钥获取明文信息，双向加密包括**对称加密**（DES,3DES,AES等）和**非对称加密**（RSA,ECC）



# 数字签名

* 简单来说就是通过提供可鉴别的数字信息验证自身身份的一种方式，一套**数字签名**通常定义两种互补的运算，一个用于**签名**，发送者持有的**私钥**；另一个用于**验证(签名)**，接受者在接受来自发送者发送的信息**验证**身份。**签名最根本的用途是能够唯一证明发送方的身份，防止中间人共计和跨域身份伪造**，因此在很多的认证体系中都会使用到**签名算法**。



### 签名和加密的区别

* 既然是加密，那肯定是不希望别人知道我的消息，所以只有我才能解密，所以可得出**公钥负责加密，私钥负责解密**；同理，既然是签名，那肯定是不希望别人冒充我发消息，只有我才能发布这个签名，所以可以得出**私钥负责签名，公钥负责验证**；





# 算法介绍

### MD5算法

* MD5(Message_Digest Algorithm-5)是计算机安全领域广泛使用的一种散列函数，用以提供消息完整性的保护，是一种信息哈希算法，它是不可逆的
* MD5广泛应用于软件的密码认证和钥匙识别上

#### 算法实现

```java
        // 定义一个字节数组，用于加密,私密数组
        byte[] secretBytes = null;
        try {
            // 用任意大小的安全单向哈希函数数据，并输出一个固定长度的哈希值
            // 实现 MD5 算法的消息摘要对象。
            MessageDigest md = MessageDigest.getInstance("MD5");
            // 对字符串进行加密
            md.update(input.getBytes());
            // 获取加密后的数据
            secretBytes = md.digest();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("加密失败");
            e.printStackTrace();
        }
```

##### 总结

MD5算法具有以下特点

* 压缩性：任意长度的数据，算出的MD5值长度都是固定的，一般需要经过处理得到一个32位或者16位字符组。
* 容易计算：从原始数据计算出MD5值最容易。
* 抗修改性：对原数据进行任何改动，哪怕只修改一个字节，所得到的MD5值都有很大区别。
* 弱碰撞性（强抗碰撞性）：一直原数据和其MD5值，想要找到一个具有相同MD5值的数据（伪造数据）是非常困难的（16^16，32^32）。



### AES算法

三个关键词：**秘钥**，**加密模式**，**填充**  

* AES(Advanced Encryption Standard)是最常见的对称加密算法（微信小程序常用），对称加密算法就是加密和解密用相同的秘钥。
* AES算法是一种典型的对称加密算法，不同于MD5这种摘要算法是不可逆的，AES是可以通过秘钥解密的，一般用于对隐私信息的保密。
* AES加密算法是密码学中的高级加密标准，该算法采用对称分组密码体制，密钥长度最少支持128位（AES128），192位（AES192），256位（AES256）秘钥越长效率越低，保密性越强；分组长度128位，算法应易于各种硬件和软件实现。

具体加密解密流程如下：

![AES](AES.png)

AES算法加密是会将明文拆分成128bit的数据块，分别进行加密，也就是如果明文长度非128bit的整数倍，则必须出现不满128bit的数据块，此时进行填充。

#### 代码实现

第一次实现原始加密（ECB方式）

```java
 		// 原始加密解密方式，生成密钥
		try {
            // 获取 Cipher 密码实例
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            // 初始化 Cipher 实例。设置执行模式以及加密密钥
            cipher.init(mode, secretKey);
            // 执行加密
            result = cipher.doFinal(contentArray);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch ( IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
```

第二次实现二次加密，本例使用base64加密方式得到输出密文

```java
		try {
            // 1 获取加密密文字节数组 
            // pwdHandler()方法是自己定义的一种密码处理方式
            byte[] cipherTextBytes = encrypt(clearText.getBytes(CHARACTER), 											pwdHandler(password));
            // 2 对密文字节数组进行BASE64 encoder 得到 BASE6输出的密文
            BASE64Encoder base64Encoder = new BASE64Encoder();
            String cipherText = base64Encoder.encode(cipherTextBytes);
            // 3 返回BASE64输出的密文
            return cipherText;
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }  
```

注意：加解密必须使用相同的模式和填充方式

说明：AES的处理单位是字节，128位的输入明文**分组P**和属于密钥K都被分成16字节，生成**明文矩阵**（即状态矩阵），状态举证通过行变化和列变化最后生成加密的密文（变化和选择的加密方式直接相关）。流程如下：

![AES加密](AES加密.png)

总结：

* AES主要特性还是：**秘钥**，**加密模式**，**填充**  ，并且加密和解密一定是互逆的（对称加密特性）
* **AES加密模式**：**ECB**/CBC/CTR/OFB/CFB
  **填充**：**pkcs5padding**/pkcs7padding/zeropadding/iso10126/ansix923
  **数据块**：**128位**/192位/256位
  **密码**：【设置加解密的密码，JAVA中有效密码为**16位**/24位/32位，
  其中**24位/32位**需要JCE（Java 密码扩展无限制权限策略文件，
  每个JDK版本对应一个JCE，百度即可找到）】
  **偏移量**：【iv偏移量，ECB不用设置】
  **输出**：base64/hex
  **字符集**：gb2312/gbk/gb18030/utf8
* 更多资料，https://www.wmathor.com/index.php/archives/1142/

### RSA算法

* 非对称加密特点：只有**公钥**（对数据进行加密）在网络中传输，**私钥**（解密）不在网络上传递，所以只要私钥不泄露，通行就是安全的。

* RSA(Rivest、Shamir、Adleman)由三位数学家设计，可以实现非对称加密。RSA是最流行的非对称加密算法之一，也被成为公钥加密，诞生于麻省理工学院。

* RSA加密实现原理：

  * 第一步：随机找两个素数P和Q，P,Q越大，越安全 n = P*Q;
  * 第二步：计算n的欧拉函数φ(n)，定义所有小于n的正整数里和n互素的整数的个数。即 φ(n) =  φ(P * Q) = φ(P - 1)φ(Q - 1) = (P - 1)(Q - 1);另一个有趣的性质是对于任意小于n且与n互素的正整数a，都有a^φ(n) mod n = 1 ;
  * 第三步：选择一个小的奇数e，1<e<φ(n)，而且有关系： e 与(p-1)(q-1)互质（增加安全性）,通过选择的e，进行计算得到 d (私钥的一部分) ，**d = e^-1 mod (p-1)(q-1)**，这里d和e模乘法逆元关系；e*d mod (p-1)(q-1)
    * **乘法是一种很好的单向函数，而单向函数是加密技术的基础。单向函数就是在一个方向上能顾很容易算出结果，但反向推导则是不切实际的。**
  * 第四步：将**（e,φ(n)）作为公钥P**，将**（d,φ(n)）作为私钥S**，并保持私钥S不可见

  ![RSA](RSA.PNG)

* **RSA算法的安全性保障来自一个重要的事实，那就是欧拉函数是乘法性质的**

* （又称公钥数字签名）是一种类似写在纸上的普通的物理签名，但是使用了公钥加密领域的技术实现，用于鉴别数字信息的方法。一套数字签名通常定义两种互补的运算，一个用于签名，另一个用于验证，但法条中的电子签章与数字签名，代表之意义并不相同，电子签章用以辨识及确认电子文件签署人身份、资格及电子文件真伪者。而数字签名则是以数学算法或其他方式运算对其加密，才形成电子签章，意即使用数字签名才创造出电子签章。---------摘自维基百科

#### 代码实现

初始化密钥

```java
		// 实例化秘钥生成器
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        // 初始化秘钥长度，KEY_LENGTH
        keyPairGenerator.initialize(KEY_LENGTH);
        // 获取秘钥对
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        // 获取RSA公钥
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        // 获取RSA私钥
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();

        // 创建 map 接受数据以及密钥
        Map<String, Key> keyMap = new HashMap<String, Key>();
        // 将公钥私钥加入
        keyMap.put(PUBLIC_KEY,rsaPublicKey);
        keyMap.put(PRIVATE_KEY,rsaPrivateKey);

        return keyMap;
```

添加数字签名

```java
		// 使用给定的编码密钥(私钥 ASN.1编码)创建一个新的钥匙，钥匙执行PKCS #8标准
        // 对数组进行复制，防止后续修改
        PKCS8EncodedKeySpec encodedKeySpec = new 																				PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
        // 返回一个转换的KeyFactory对象指定算法的公钥/私钥。
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

        // 获取私钥
        PrivateKey privateKey = keyFactory.generatePrivate(encodedKeySpec);

        // 使用签名算法实例化Signature签名对象，用于生产和验证数字签名
        Signature signature = Signature.getInstance(SIGN_ALGORITHM);
        // 使用签名私钥进行初始化
        signature.initSign(privateKey);
        // 更新需要签名的数据 data数据，待签署数据
        signature.update(data.getBytes());
        // 进行签名
        byte[] signed = signature.sign();

        return signed;
```

公钥验证

```java
		// 使用给定的编码密钥(公钥 ASN.1)创建一个新的钥匙，钥匙执行X.509标准
        // 对数组进行复制，防止后续修改
        X509EncodedKeySpec encodedKeySpec = new 																				X509EncodedKeySpec(rsaPublicKey.getEncoded());
        // 实例化KeyFactory
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        // 获取签名公钥
        PublicKey publicKey = keyFactory.generatePublic(encodedKeySpec);

        Signature signature = Signature.getInstance(SIGN_ALGORITHM);
        // 初始化此对象以进行验证
        signature.initVerify(publicKey);
        // 更新签名数据
        signature.update(data.getBytes());
        boolean verified = signature.verify(bytes);

        return verified;
```

说明：

* "对极大整数做因数分解的难度决定了RSA算法的可靠性。换言之，对一极大整数做因数分解愈困难，RSA算法愈可靠。
* 假如有人找到一种快速因数分解的算法，那么RSA的可靠性就会极度下降。但找到这样的算法的可能性是非常小的。今天只有短的RSA密钥才可能被**暴力破解**。到2008年为止，世界上还没有任何可靠的攻击RSA算法的方式。
* 只要密钥长度足够长，用RSA加密的信息实际上是不能被解破的。"

举例：

​		当前计算机的CPU运算速度是2.4GHZ每秒运算2400，000，000次，也就是十进制的10位，那么采用长度1024位的加密时，1024*1024位，可想而知破解一次密码CPU需要运算多少年。

总结：

* RSA到目前为止依然是最安全的密码之一，被应用在众多的网络通信和交易当中
* RSA还常用语软件注册机当中，作为验证的主要方式，一般会对产生后的密文进行分开文件存储，添加特殊符号等处理作为最终的密码处理方式，但是相对的密文的解释肯定也在某一文件中存在，作为验证方式。
* 更多资料：https://www.cnblogs.com/idreamo/p/9411265.html



