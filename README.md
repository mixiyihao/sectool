### JAVA 安全修复工具


使用工厂类SecurityUtil获取相应的对象，每个类型都有两种方式，一种进行修复之后无害参数，一种是判断是否有害参数, 详情具体方式参考接口里面的注释

#### SSRF 修复
目前修复方式有两种 <br>
判断内网接口与白名单接口<br>
```java
public interface SSRFProtect {
    boolean isSafeByPrivateNetwork(String url, boolean confirm302RedirectClose);
    boolean isSafeByWhiteList(String url, List<String> whiteList, boolean confirm302RedirectClose);
}
```
<font face="red">注意：</font> 使用该方法是，由于无法判断使用的框架，所以无法限制302跳转，使用前必须限制302防止跳转 <br>
<font face="red">余留问题：</font> DNS rebinding 内网判断目前暂未实现 <br>

#### XXE 修复
xxe 的修复方式是直接禁止本地与远程dtd加载，原理是通过已知的解析xml类对它进行限制
目前实现的有一下类<br>
DocumentBuilderFactory;SAXParserFactory;SAXTransformerFactory;SAXBuilder;SAXReader;XMLReader;TransformerFactory;SchemaFactory

```java
public interface XXEProtect {
    boolean repaireXXE(Object object);
}
```


#### XSS 修复
目前是通过实体编码方式与判断是否有不正常的标签
```java
public interface XSSProtect {
    String repairXSSByHTMLEncoding(String params);
    boolean isSafe(String params);
}
```

#### 任意文件上传
任意文件上传判断文件是否为固定类型与防止目录穿越写漏洞

```java
public interface ArbitraryFileUploadProtect { 
    boolean checkFile(String filepath, Type type);
    boolean checkFile(String filepath);
    String checkFileAndReNameFile(String filepath, Type type);
}
```

#### SQL注入
按理来说不推荐使用这种方式修复，但是总有会碰到有些功能使用拼接的话事半功倍，所以有了这个修复方式，已修复分字符转，整形与order by 的不同修复方式
<br>原理：<br>
字符过滤', ", \ 这些特殊字符，该无法对宽字节进行防御；<br>
整形强转<br>
排序白名单方式<br>

```java
public interface SQLInjectionProtect {
     String filterIllegalCharacterToParaphrased(String params);
     String filterSpecialCharactersToEmpty(String params);
     boolean checkSafeByIllegalCharacters(String params);
     boolean checkSafeByIntegerArrayHasIllegalString(String[] params);
     boolean checkSafeByOrderBy(String orderby, List<String> whiteList);
}
```

#### 目录穿越漏洞
将父节点过滤. 
```java
public interface DirectoryTraversalProtect {
    String repairPathByfilterSpot(String filePath);
    boolean isSafeByRelativePath(String filePath);
}
```

#### 使用方法
```java
class Demo{
    
    public static void  main(String args[]){
    SecurityUtil instance = SecurityUtil.getInstance();
    ArbitraryFileUploadProtect arbitraryFile = instance.getArbitraryFile();
    arbitraryFile.checkFile("icon.png", ArbitraryFileUploadProtect.Type.IMAGE);
}
}
```
