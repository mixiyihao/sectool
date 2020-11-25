package com.mixiyihao.security.tool;

/**
  待收集能够造成XXE的参数，然后进行修复

 */
public interface XXEProtect {
    /**
     * 解析XML的时候对XXE 进行修复, 该方法一定是创建对象之后立即调用，目前实现了以下对象的修复方式
     *   DocumentBuilderFactory;
     *   SAXParserFactory;
     *   SAXTransformerFactory
     *   SAXBuilder
     *   SAXReader
     *   XMLReader
     *   TransformerFactory
     *   SchemaFactory
       修复方式参考以下链接：
        https://blog.spoock.com/2018/10/23/java-xxe/
     * @param object 需要修复的对象
     * @return true 设置成功，false 设置失败，请进行百度相关解析类防止XXE的方法
     */
    public boolean repaireXXE(Object object);

}
