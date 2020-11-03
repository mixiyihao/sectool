package com.mixiyihao.security.tool;

import java.util.List;

/***
 @author wuguofu
 @date 2020.10.27
 @version 1.0.0

 该接口是判断防御SSRF的防御

 */
public interface SSRFProtect {
    /***

     判断是否内网，理论上可以的，但是如何判断是否内网判断技术过多，实现不全，有部分可以绕过, 推荐使用白名单的方式
     @param url 通过url 待检测的url
     @param confirm302RedirectClose 请确认接口已经关闭302跳转，例如Okhttp使用前，关闭302跳转的设置new OkHttpClient().newBuilder().followRedirects(false)，使用HttpURLConnection connection; connection.setInstanceFollowRedirects(true);其他框架等差不多这样，否则有可能通过302跳转，绕过SSRF
     @return 如果安全则返回true，否则返回false
     */
    public  boolean isSafeByPrivateNetwork(String url, boolean confirm302RedirectClose);
    /**
     通过白名单的方式进行限制访问
     @param url 参数url
     @param whiteList 白名单域名
     @param confirm302RedirectClose 请确认接口已经关闭302跳转，例如Okhttp使用前，关闭302跳转的设置new OkHttpClient().newBuilder().followRedirects(false)，其他框架等差不多这样,如需使用，请与安全工作人员商量讨论,否则有可能通过302跳转，绕过SSRF
     @return true 安全的, false 不安全
     */
    public  boolean isSafeByWhiteList(String url, List<String> whiteList, boolean confirm302RedirectClose);
    public  boolean isSafeByWhiteList(String url, String[] whiteList, boolean confirm302RedirectClose);
}
