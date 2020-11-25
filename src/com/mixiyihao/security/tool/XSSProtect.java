package com.mixiyihao.security.tool;

/**
 * 修复XSS的方式
 *
 */

public interface XSSProtect {
    /**
     *  通过实体编码对XSS 进行修复， 底层实现通过esapi 抄过来的
     * @param params
     * @return 返回实体编码之后的XSS
     */
    public String repairXSSByHTMLEncoding(String params);


    /**
     * 判断是否有XSS 的代码
     * @param params
     * @return
     */
    public boolean isSafe(String params);
}
