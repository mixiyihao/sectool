package com.mixiyihao.security.tool;

/**

 任意文件上传漏洞修复方式：
 1. 上传文件目录设置只读只写，并限制该目录中
 2. 上传文件白名单
 3. 对文件进行重命名，防止其他幺儿子出现

 */


public interface ArbitraryFileUploadProtect {
    /**
     * 类型枚举
     */
    enum Type{
        IMAGE, VEDIO, FILE
    }

    /**
     * 图片类型
     * jpg, gif, png, bmp
     */
    static String whiteListByImageFormat[] = {"jpg","gif", "png","bmp"};
    /**
     * 文件类型xls， xml, zip, doc, xlsx, svg,txt, docx
     */
    static String whiteListByFileFormat [] = {"xls","xml", "zip","doc","xlsx","svg", "txt","docx"};
    /**
     * 视频类型mp3, mp4, rmvb,3gp,flv,rm, avi
     */
    static String whiteListByVedioFormat[] = {"mp3","mp4", "rmvb","3gp","flv","mv","rm","avi"};

    /**
     *
     * 上传白名单检测，并防止目录穿越
     * @param filepath 文件路径
     * @param type 白名单检测代码
     * @return true安全的，false 不安全的
     */
    public boolean checkFile(String filepath, Type type);
    /**
     * 检测是否包含特殊字符，防止目录穿越
     @param filepath
     @return true 是安全的，false为不安全的
     */
    public boolean checkFile(String filepath);

    /**
     * 对文件进行安全检测，如果无风险则进行重命名
     * @param filepath
     * @return null 代表存在风险，否则就是重命名之后的数据
     */
    public String checkFileAndReNameFile(String filepath, Type type);


}
