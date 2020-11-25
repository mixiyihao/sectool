package com.mixiyihao.security.tool;


import com.mixiyihao.security.tool.impl.*;

public class SecurityUtil {
    private static SecurityUtil mSecurityUtil = new SecurityUtil();
    private SSRFProtect mSSRFProtect;
    private SQLInjectionProtect mSQLInjectionProtect;
    private DirectoryTraversalProtect mDirectoryTraversalProtect;
    private XSSProtect mXSSProtect;
    private XXEProtect mXXEprotect;
    private ArbitraryFileUploadProtect mArbitraryFile;
    private SecurityUtil(){
        mSSRFProtect = new SSRFProtectImpl();
        mSQLInjectionProtect = new SQLInjectionProtectImpl();
        mXSSProtect = new XSSProtectImpl();
        mXXEprotect = new XXEProtectImpl();
        mDirectoryTraversalProtect = new DirectoryTraversalProtectImpl();
        mArbitraryFile = new ArbitraryFileUploadProtectImpl();
    }
    public static SecurityUtil getInstance(){
        return mSecurityUtil;
    }

    public SSRFProtect getSSRFCheckSecurity(){
        return mSSRFProtect;
    }

    public SQLInjectionProtect getSQLInjectionProtect() {
        return mSQLInjectionProtect;
    }

    public XSSProtect getXSSProtect() {
        return mXSSProtect;
    }

    public XXEProtect getXXEprotect() {
        return mXXEprotect;
    }

    public ArbitraryFileUploadProtect getArbitraryFile() {
        return mArbitraryFile;
    }
    public DirectoryTraversalProtect getDirectoryTraversalProtect() {
        return mDirectoryTraversalProtect;
    }
}
