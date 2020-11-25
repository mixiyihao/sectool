package com.mixiyihao.security.tool;


import java.io.File;

/**
 @author wuguofu


 第一种： （推荐）任意文件下载漏洞与任意文件上传漏洞修复方式，上传到制定资源服务器，比如阿里云OSS 存储对象

 第二种：
 1. 限制文件读取方法，禁止访问目录绝对路径。
 2. 限制文件读取文件类型，如这里仅可读取图片类型。
 3. 禁止参数中，出现"."等特殊符号。
 4. 条件允许的情况下，建议以id传参的方式，绑定对应下载文件。
 */
public interface DirectoryTraversalProtect {
    /**
     过滤 "." 的方式，然后直接返回路径，防止目录穿越
        比如 xxx/../../../../etc/passwd  === > xxx/////etc/passwd
     * @param filePath 相对路径
     * @return 返回过滤. 之后的路径
     */

    public String repairPathByfilterSpot(String filePath);
    /**
     判断相对路径是否安全
     * @param filePath 路径
     * @return
     */
    public boolean isSafeByRelativePath(String filePath);


}
