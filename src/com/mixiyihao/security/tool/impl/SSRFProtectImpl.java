package com.mixiyihao.security.tool.impl;

;
import com.mixiyihao.security.tool.SSRFProtect;
import sun.net.util.IPAddressUtil;

import java.net.*;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class SSRFProtectImpl implements SSRFProtect {


    // 正则表达式主域名
    public static String RE_TOP = "(\\w*\\.?){1}\\.(com.cn|net.cn|gov.cn|org\\.nz|org.cn|com|net|org|gov|cc|biz|info|cn|co)$";
    // 二级域名
    public static String RE_2TOP = "(\\w*\\.?){2}\\.(com.cn|net.cn|gov.cn|org\\.nz|org.cn|com|net|org|gov|cc|biz|info|cn|co)$";
    // 判断是否为IP
    //public static String RE_IP = "^((25[0-5]|2[0-4]\\\\d|1\\\\d{2}|[1-9]?\\\\d)\\\\.){3}(25[0-5]|2[0-4]\\\\d|1\\\\d{2}|[1-9]?\\\\d)$";
    public static String RE_IP_HOST = "^([1-9]|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3}$";
    public static String RE_DOMAIN = "^(\\w+\\.)+\\w+$";
    /**
     *  判断是否安全的协议,允许http/https协议
     * @param protocol 协议
     * @return true 安全，false 不安全
     */
    private boolean isSafeProtocol(String protocol){
        if("https".equals(protocol)||"http".equals(protocol)){
            return true;
        }

        return false;
    }

    /**
      通过官方api进行判断是LocalAddress
     * @param host
     * @return
     */
    private boolean isSafeByInetAddress(String host){
        try {
            InetAddress inetAddress = InetAddress.getByName(host);
            return  inetAddress.isAnyLocalAddress() || inetAddress.isLinkLocalAddress()||inetAddress.isLoopbackAddress();
        } catch (UnknownHostException e) {
            return false;
        }
    }

    /**
     通过host获取二级域名
     * @param host 域名
     * @return 主域名
     */
    private String getTopDomainByHost(String host){

        Pattern r = Pattern.compile(RE_TOP);
        Matcher matcher = r.matcher(host);
        if(matcher.find()){
            String group = matcher.group(0);
            return group;
        }else{
            if(isLegalIp(host)){
                return host;
            }
            return null;
        }
    }

    /**
     * 判断是否合法IP
     * @param host 域名
     * @return true 合法的，false 不合法
     */
    private boolean isLegalHost(String host){
        // Pattern r = Pattern.compile(RE_TOP);
        // Matcher matcher = r.matcher(host);
        //boolean isIp = host.matches(RE_IP);
        // 过滤localhost
        // 过滤十六进制
        // 判断是否合法ip
        if(isLegalIp(host)){

            // 判断是否内网
            if(isInternalIp(host)){ //如果是内网就返回false,否则true
                return false;
            }

            return true;

        }else {
            // 非ip ，则通过域名获取ip，进行内网判断
            try {
                InetAddress[] allByName = InetAddress.getAllByName(host);
                for (InetAddress address:allByName) {
                    // System.out.println(address);
                    String hostAddress = address.getHostAddress();
                    // System.out.println(hostAddress);
                    byte[] ip = address.getAddress();
                    if(isInternalIp(ip)) {
                        return false;
                    }
                }
                return true;
            } catch (UnknownHostException e) {
                return false;
            }}
    }

    /**
     * 判断合法ip
     * @param host
     * @return
     */
    private boolean isLegalIp(String host){
        Pattern pattern = Pattern.compile(RE_IP_HOST);
        Matcher matcher = pattern.matcher(host);
        return matcher.find();
    }

    /**
     * 判断是否内网ip
     * @return
     */
    private boolean isInternalIp(String ip){
        byte[] addr = IPAddressUtil.textToNumericFormatV4(ip);
        return isInternalIp(addr);
    }

    /**
     * 判断是否内网ip
     * @param addr
     * @return
     */
    private boolean isInternalIp(byte[] addr){
        final byte b0 = addr[0];
        final byte b1 = addr[1];
        //10.x.x.x/8
        final byte SECTION_1 = 0x0A;
        //172.16.x.x/12
        final byte SECTION_2 = (byte) 0xAC;
        final byte SECTION_3 = (byte) 0x10;
        final byte SECTION_4 = (byte) 0x1F;
        //192.168.x.x/16
        final byte SECTION_5 = (byte) 0xC0;
        final byte SECTION_6 = (byte) 0xA8;
        switch (b0) {
            case SECTION_1:
                return true;
            case SECTION_2:
                if (b1 >= SECTION_3 && b1 <= SECTION_4) {
                    return true;
                }
            case SECTION_5:
                switch (b1) {
                    case SECTION_6:
                        return true;
                }
            default:
                return false;
        }

    }

    /**
     *
     * @param uri
     * @param confirm302RedirectClose
     * @return
     */
    private boolean commanCheck(URI uri, boolean confirm302RedirectClose){

        if(uri==null){
            return false;
        }
        // 确认已经关闭重定向
        if(!confirm302RedirectClose){
            throw new IllegalStateException("请确定已经对302跳转进行限制了，否则有可能对302跳转绕过");
        }
        String host = uri.getHost();
        // 判断是否正常的协议
        if(!isSafeProtocol(uri.getScheme())){
            return false;
        }

        // 判断是否localhost/127.0.0.1
        boolean isSafe = isSafeByInetAddress(host);
        // System.out.println(!isSafe);
        return !isSafe;
    }






    @Override
    public boolean isSafeByPrivateNetwork(String url, boolean confirm302RedirectClose) {
        /**
         1）限制协议为HTTP、HTTPS
         2）禁止302跳转
         3）设置URL白名单或者限制内网IP

         相关绕过链接： https://www.secpulse.com/archives/65832.html
         * @param url 待检测的url
         * @return true是安全的，false不安全的
         */
        // 如果为空，则返回true
        if(url == null||url.isEmpty()){
            return true;
        }
        URI uri = URI.create(url);
        if(!commanCheck(uri, confirm302RedirectClose)){
            return false;
        }

        // 判断host是否为ip/域名
        return isLegalHost(uri.getHost());

       // return false;
    }


    @Override
    public boolean isSafeByWhiteList(String url, List<String> whiteList, boolean confirm302RedirectClose) {
        if(url == null || url.isEmpty()){
            return true;
        }
        URI uri = URI.create(url);
        if(!confirm302RedirectClose){
            return false;
        }
        // 白名单需要么检测是否厄内网？？？？
//        if(!commanCheck(uri, confirm302RedirectClose)){
//            return false;
//        }
        // String host = uri.getHost();
        // 获取主域名
        String topDomainByHost = getTopDomainByHost(uri.getHost());
        //白名单判断
        return whiteList.contains(topDomainByHost);
    }

    @Override
    public boolean isSafeByWhiteList(String url, String[] whiteList, boolean confirm302RedirectClose) {
        List<String> whiteLists = Arrays.asList(whiteList);
        return isSafeByWhiteList(url, whiteLists, confirm302RedirectClose);
    }



    public static void main(String args[]) throws MalformedURLException {
        SSRFProtect ssrf = new SSRFProtectImpl();
        String p = "254.255.255.255";
        String username = "chenpeng"
        String password = "123456!@123";
        String whiteList[] = {"172.16.1.1","xhs.com"};
//        boolean safeByWhiteList = ssrf.isSafeByWhiteList(p, whiteList, true);
//
//        System.out.println(safeByWhiteList);
        String RE_IP = "([1-9]|[1-9]\\\\d|1\\\\d{2}|2[0-4]\\\\d|25[0-5])(\\\\.(\\\\d|[1-9]\\\\d|1\\\\d{2}|2[0-4]\\\\d|25[0-5])){3}";
        String ip = "^([1-9]|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3}$";
        Pattern pattern = Pattern.compile(ip);
        Matcher matcher = pattern.matcher(p);
        System.out.println(matcher.matches());
       // System.out.println(p.matches(RE_IP));

        /*
        // 攻击本地的方法
        String urls[] = {
                "https://www.baidu.com.xip.io",
                "http://soc.saicm.local/",
                "https://api.xhs.com",
                "https://10.0.0.1.xip.io:443",
                "http://2130706433/",
                "http://012.012.0.1:443",
                "http://10.10.1.1/",
                "url:http://127.0.0.1",
                "url:http://localhost",
                "http://[::]:80/",
                "http://www.baidu.com@10.0.0.1",
                "http://dwz.cn/11SMa" ,
                "http://10.0.0.1.xip.io/",
                "http://www.owasp.org.127.0.0.1.xip.io/"
        };


        // 利用 @ 方法
        // 利用短地址
       // String shortLocalUrl = "http://dwz.cn/11SMa";
        // 利用特殊域名
        String especailUrl1 = "";
        String especailUrl2 = "";
        // 八进制
        String especailUrl3 = "";
        // 利用十六进制
        String hexUrl = "http://2130706433/";
        String especailUrl4= "https://10.0.0.1.xip.io:443";
        String normalUrl = "https://api.xhs.com";

        // 利用Enclosed alphanumerics
        SSRFProtect ssrf = new SSRFProtectImpl();
        ArrayList <String> whiteList = new ArrayList();
        whiteList.add("www.baidu.com");

        for(int i=0;i<urls.length;i++){
            String url = urls[i];
            // url = "http://012.012.0.1:443";
            boolean safeByPrivateNetwork = ssrf.isSafeByPrivateNetwork(url, true);
            System.out.println(url+ "---------------------"+ safeByPrivateNetwork);

        }
    */

    }
}
