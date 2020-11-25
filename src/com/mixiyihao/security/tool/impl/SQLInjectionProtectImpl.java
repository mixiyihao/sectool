package com.mixiyihao.security.tool.impl;

import com.mixiyihao.security.tool.SQLInjectionProtect;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SQLInjectionProtectImpl implements SQLInjectionProtect {


    @Override
    public String filterIllegalCharacterToParaphrased(String params) {
        if(params == null || params.isEmpty()){
            return params;
        }
        params = params.replace("\\", "\\\\");
        params = params.replace("'", "\\\'");
        params = params.replace("\"", "\\\"");

        return params;
    }

    @Override
    public String filterSpecialCharactersToEmpty(String params) {
        if(params == null || params.isEmpty()){
            return params;
        }
        params = params.replace("\\", "");
        params = params.replace("'", "");
        params = params.replace("\"", "");

        return params;
    }

    @Override
    public boolean checkSafeByIllegalCharacters(String params) {
        if(params == null || params.isEmpty()){
            return true;
        }
        String lowParams = params.toLowerCase();
        Pattern pattern= Pattern.compile("\\b(and|exec|insert|select|drop|grant|alter|delete|update|count|chr|mid|master|truncate|char|declare|or)\\b|(\\*|;|\\+|'|\"|%)");
        Matcher matcher=pattern.matcher(lowParams);
        return !matcher.find();
    }

    @Override
    public boolean checkSafeByIntegerArrayHasIllegalString(String[] params) {
        for(String value: params){
           try {
               Integer.parseInt(value);
           }catch (Exception e){
               return false;
           }
        }
        return true;
    }

    @Override
    public boolean checkSafeByOrderBy(String orderby, List<String> whiteList) {
        if(orderby == null || orderby.isEmpty()){
            return true;
        }
        if(whiteList == null||whiteList.isEmpty()){
            return false;
        }

        return whiteList.contains(orderby);
    }


    public static void main(String args[]) throws  Exception{
        SQLInjectionProtect sqltool = new SQLInjectionProtectImpl();
        String 数字型 = "2-(case when 1=1 then 1 else 0 end)"; // 当时数字型的时候就好绕了
        String 字符型_单引号 = "test'"; //字符型的话，有单引号，当使用gbk编码的时候，就容易绕过
        String 字符型_gbk = "test%bf%27 %df%27 %aa%27"; //GBK模式
        String 字符型_双引号 = "test\"\\";
        String 字符型_注释符 = "test*";
        // String decode = URLDecoder.decode(字符型_gbk, "utf-8");
        // System.out.println(decode);
        // System.out.println("\\\"");
        boolean b = sqltool.checkSafeByIllegalCharacters(字符型_双引号);
        String specialCharacters = "'\" \\' or test";
        specialCharacters = sqltool.filterIllegalCharacterToParaphrased(specialCharacters);

        System.out.println(specialCharacters);

    }



}
