package com.mixiyihao.security.tool.impl;

public class ValidationException  extends Exception{
    public ValidationException(String userMessage, String logMessage){
        super(userMessage + ":"+logMessage);
    }
}
